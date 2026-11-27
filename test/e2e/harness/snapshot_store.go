package harness

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// StoredObject represents an immutable artifact file discovered inside SnapshotStore rootDir.
type StoredObject struct {
	RelPath   string
	AbsPath   string
	SHA256    string
	SizeBytes int64
	ModTime   time.Time
}

// ArchiveEntryInfo holds metadata and content extracted from a stored tar.gz archive.
type ArchiveEntryInfo struct {
	Name     string
	Linkname string
	Typeflag byte
	Mode     int64
	Size     int64
	Content  []byte
}

// SnapshotStoreHelper provides layout-agnostic inspection and fault injection for local FS SnapshotStore.
type SnapshotStoreHelper struct {
	t       testing.TB
	rootDir string

	mu          sync.Mutex
	outageOn    bool
	renamedPath string
}

// NewSnapshotStoreHelper initializes a local SnapshotStoreHelper at rootDir (or t.TempDir() if empty).
// Registers unconditional cleanup to restore permissions if SimulateOutage(true) was left active.
func NewSnapshotStoreHelper(t testing.TB, rootDir string) *SnapshotStoreHelper {
	t.Helper()
	if rootDir == "" {
		rootDir = filepath.Join(t.TempDir(), "snapshot-store")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("mkdir snapshot store root %q: %v", rootDir, err)
	}
	s := &SnapshotStoreHelper{
		t:       t,
		rootDir: rootDir,
	}
	t.Cleanup(func() {
		_ = s.SimulateOutage(false)
	})
	return s
}

// RootDir returns the filesystem root path of the SnapshotStore.
func (s *SnapshotStoreHelper) RootDir() string {
	return s.rootDir
}

// WriteObject writes bytes to relPath under rootDir (used in harness setup/self-tests) and returns StoredObject.
func (s *SnapshotStoreHelper) WriteObject(relPath string, data []byte) (StoredObject, error) {
	s.mu.Lock()
	outage := s.outageOn
	s.mu.Unlock()
	if outage {
		return StoredObject{}, errors.New("snapshot store outage simulated")
	}
	cleanRel := filepath.Clean(relPath)
	if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
		return StoredObject{}, fmt.Errorf("invalid relative path %q", relPath)
	}
	abs := filepath.Join(s.rootDir, cleanRel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return StoredObject{}, err
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return StoredObject{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return StoredObject{}, err
	}
	return StoredObject{
		RelPath:   filepath.ToSlash(cleanRel),
		AbsPath:   abs,
		SHA256:    SHA256Hex(data),
		SizeBytes: info.Size(),
		ModTime:   info.ModTime().UTC(),
	}, nil
}

// ListObjects walks rootDir and returns all files hashed with SHA-256, independent of internal FS layout.
func (s *SnapshotStoreHelper) ListObjects() ([]StoredObject, error) {
	s.mu.Lock()
	outage := s.outageOn
	s.mu.Unlock()
	if outage {
		return nil, errors.New("snapshot store outage simulated")
	}

	var objs []StoredObject
	err := filepath.WalkDir(s.rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		rel, err := filepath.Rel(s.rootDir, path)
		if err != nil {
			rel = path
		}
		objs = append(objs, StoredObject{
			RelPath:   filepath.ToSlash(rel),
			AbsPath:   path,
			SHA256:    hex.EncodeToString(h.Sum(nil)),
			SizeBytes: info.Size(),
			ModTime:   info.ModTime().UTC(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(objs, func(i, j int) bool {
		return objs[i].RelPath < objs[j].RelPath
	})
	return objs, nil
}

// FindBySHA256 locates a stored object by SHA-256 hex digest (accepts optional "sha256:" prefix).
func (s *SnapshotStoreHelper) FindBySHA256(sha256Hex string) (*StoredObject, error) {
	want := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sha256Hex), "sha256:"))
	objs, err := s.ListObjects()
	if err != nil {
		return nil, err
	}
	for i := range objs {
		if objs[i].SHA256 == want {
			cp := objs[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("snapshot object with sha256 %q not found", want)
}

// FindByKeySuffix locates a stored object whose relative path ends with key.
func (s *SnapshotStoreHelper) FindByKeySuffix(key string) (*StoredObject, error) {
	clean := filepath.ToSlash(strings.TrimPrefix(key, "/"))
	objs, err := s.ListObjects()
	if err != nil {
		return nil, err
	}
	for i := range objs {
		if objs[i].RelPath == clean || strings.HasSuffix(objs[i].RelPath, "/"+clean) || strings.HasSuffix(objs[i].RelPath, clean) {
			cp := objs[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("snapshot object matching key suffix %q not found", key)
}

// ReadBytes reads the raw bytes of a StoredObject.
func (s *SnapshotStoreHelper) ReadBytes(obj StoredObject) ([]byte, error) {
	s.mu.Lock()
	outage := s.outageOn
	s.mu.Unlock()
	if outage {
		return nil, errors.New("snapshot store outage simulated")
	}
	return os.ReadFile(obj.AbsPath)
}

// InspectTarGz extracts entries from a tar.gz payload for verification.
func (s *SnapshotStoreHelper) InspectTarGz(data []byte) ([]ArchiveEntryInfo, error) {
	entries, err := ExtractTarGz(data)
	if err != nil {
		return nil, err
	}
	out := make([]ArchiveEntryInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, ArchiveEntryInfo{
			Name:     e.Name,
			Linkname: e.Linkname,
			Typeflag: e.Typeflag,
			Mode:     e.Mode,
			Size:     int64(len(e.Body)),
			Content:  e.Body,
		})
	}
	return out, nil
}

// CheckArchiveNoSecretLeak scans tar.gz archive paths, linknames, and file contents for any secrets
// or GitHub credential patterns, returning an error if any leak is found.
func (s *SnapshotStoreHelper) CheckArchiveNoSecretLeak(tarGz []byte, secrets ...string) error {
	entries, err := ExtractTarGz(tarGz)
	if err != nil {
		return fmt.Errorf("inspect tar.gz for secrets: %w", err)
	}
	for _, e := range entries {
		if leaks := FindSecretOrEncodedLeaks(e.Name, secrets...); len(leaks) > 0 {
			return fmt.Errorf("secret leaked in archive entry path %q: %s", e.Name, strings.Join(leaks, ", "))
		}
		if e.Linkname != "" {
			if leaks := FindSecretOrEncodedLeaks(e.Linkname, secrets...); len(leaks) > 0 {
				return fmt.Errorf("secret leaked in archive entry linkname %q -> %q: %s", e.Name, e.Linkname, strings.Join(leaks, ", "))
			}
		}
		if leaks := FindSecretOrEncodedLeaks(string(e.Body), secrets...); len(leaks) > 0 {
			return fmt.Errorf("secret leaked in archive entry %q: %s", e.Name, strings.Join(leaks, ", "))
		}
		if strings.Contains(string(e.Body), "x-access-token:") || strings.Contains(string(e.Body), "BEGIN RSA PRIVATE KEY") ||
			strings.Contains(e.Name, "x-access-token:") || strings.Contains(e.Linkname, "x-access-token:") {
			return fmt.Errorf("credential marker leaked in archive entry %q", e.Name)
		}
	}
	return nil
}

// AssertArchiveNoSecretLeak fails t if tarGz contains any secret or GitHub credential marker.
func (s *SnapshotStoreHelper) AssertArchiveNoSecretLeak(t testing.TB, tarGz []byte, secrets ...string) {
	t.Helper()
	if err := s.CheckArchiveNoSecretLeak(tarGz, secrets...); err != nil {
		t.Fatal(err)
	}
}

// AssertArchiveGitSanitised verifies an ingress archive with optional .git metadata stripped hooks,
// credential helpers, unsafe config keys (fsmonitor, sshCommand), and remote tokens.
func (s *SnapshotStoreHelper) AssertArchiveGitSanitised(t testing.TB, tarGz []byte) {
	t.Helper()
	entries, err := ExtractTarGz(tarGz)
	if err != nil {
		t.Fatalf("AssertArchiveGitSanitised failed to parse archive: %v", err)
	}
	for _, e := range entries {
		norm := filepath.ToSlash(strings.TrimPrefix(e.Name, "./"))
		if strings.HasPrefix(norm, ".git/hooks/") && e.Typeflag == tar.TypeReg {
			t.Fatalf("unsanitised .git hook present in ingress archive: %q", norm)
		}
		if norm == ".git/config" {
			body := strings.ToLower(string(e.Body))
			for _, forbidden := range []string{"fsmonitor", "sshcommand", "credential", "x-access-token", "ghs_", "ghp_"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("unsanitised .git/config contains %q", forbidden)
				}
			}
		}
	}
}

// ObjectCount returns the total number of files currently stored in rootDir.
func (s *SnapshotStoreHelper) ObjectCount() (int, error) {
	objs, err := s.ListObjects()
	if err != nil {
		return 0, err
	}
	return len(objs), nil
}

// SimulateOutage blocks/unblocks SnapshotStore filesystem access cleanly for RG-10 fault injection.
func (s *SnapshotStoreHelper) SimulateOutage(enable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if enable == s.outageOn {
		return nil
	}
	if enable {
		s.outageOn = true
		if os.Geteuid() == 0 {
			// chmod 0000 does not block UID 0; rename directory temporarily instead.
			backup := s.rootDir + ".outage-backup"
			if err := os.Rename(s.rootDir, backup); err != nil {
				return err
			}
			s.renamedPath = backup
			return nil
		}
		return os.Chmod(s.rootDir, 0o000)
	}

	s.outageOn = false
	if s.renamedPath != "" {
		if err := os.Rename(s.renamedPath, s.rootDir); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.renamedPath = ""
		return nil
	}
	if _, err := os.Stat(s.rootDir); err == nil {
		return os.Chmod(s.rootDir, 0o755)
	}
	return nil
}
