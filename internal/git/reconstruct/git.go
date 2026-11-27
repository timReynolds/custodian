package reconstruct

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
)

type rawGitChange struct {
	ChangeType string
	Path       string
	OldPath    string
}

type diffArtifacts struct {
	TreeDigest   string
	ChangedFiles []ChangedFile
	UnifiedDiff  string
	DiffDigest   string
}

func runHardenedGit(ctx context.Context, gitBin string, env []string, workDir string, args ...string) ([]byte, error) {
	baseFlags := checkout.HardenedGitFlags(false)
	allArgs := make([]string, 0, len(baseFlags)+2+len(args))
	allArgs = append(allArgs, baseFlags...)
	allArgs = append(allArgs, "-C", workDir)
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, gitBin, allArgs...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
			return nil, domain.WrapError(domain.ErrUnavailable, "GIT_RECONSTRUCT_TIMEOUT", "git reconstruction command timed out or cancelled", err)
		}
		sanitized := checkout.SanitizeGitOutput(stderr.String())
		return nil, domain.WrapError(domain.ErrUnprocessable, "GIT_RECONSTRUCT_FAILED", fmt.Sprintf("git command failed: %s", sanitized), err)
	}
	return stdout.Bytes(), nil
}

func stageAndDiff(ctx context.Context, gitBin, workDir, baseSHA string) (diffArtifacts, error) {
	homeDir, err := os.MkdirTemp("", "custodian-reconstruct-home-*")
	if err != nil {
		return diffArtifacts{}, domain.WrapError(domain.ErrInternal, "RECONSTRUCT_ENV_FAILED", "failed creating isolated git home directory", err)
	}
	if err := os.Chmod(homeDir, 0o700); err != nil {
		_ = os.RemoveAll(homeDir)
		return diffArtifacts{}, domain.WrapError(domain.ErrInternal, "RECONSTRUCT_ENV_FAILED", "failed securing isolated git home directory", err)
	}
	defer os.RemoveAll(homeDir)

	env := checkout.CleanGitEnv(homeDir, false, false, "", "")

	// Clear any base checkout index entries first so case-only or Unicode NFC/NFD
	// renames on case/normalization-insensitive filesystems (e.g., APFS) cannot
	// leave stale entries in .git/index alongside the newly extracted paths.
	if _, err := runHardenedGit(ctx, gitBin, env, workDir, "read-tree", "--empty"); err != nil {
		return diffArtifacts{}, err
	}

	// Explicitly override core.filemode=false (written by checkout.SanitizeGitMetadata)
	// so 0755 executable files retain mode 100755, disable core.precomposeUnicode so
	// exact extracted path bytes match CANONICAL_TREE across macOS/Linux, and pass -f
	// so .gitignore-matched egress files are still captured in CANONICAL_TREE and CANONICAL_DIFF.
	if _, err := runHardenedGit(ctx, gitBin, env, workDir, "-c", "core.precomposeUnicode=false", "-c", "core.filemode=true", "add", "-A", "-f", "--", "."); err != nil {
		return diffArtifacts{}, err
	}

	treeOut, err := runHardenedGit(ctx, gitBin, env, workDir, "write-tree")
	if err != nil {
		return diffArtifacts{}, err
	}
	treeDigest, err := domain.ParseGitSHA(string(treeOut))
	if err != nil {
		return diffArtifacts{}, domain.WrapError(domain.ErrInternal, "INVALID_TREE_DIGEST", "git write-tree returned invalid digest", err)
	}

	nameStatusOut, err := runHardenedGit(ctx, gitBin, env, workDir,
		"-c", "diff.renames=true",
		"-c", "core.quotepath=false",
		"diff", "--cached", "--name-status", "-M", "-z", baseSHA, "--",
	)
	if err != nil {
		return diffArtifacts{}, err
	}

	rawChanges, err := parseNameStatusZ(nameStatusOut)
	if err != nil {
		return diffArtifacts{}, err
	}

	changedFiles, err := enrichChangedFiles(workDir, rawChanges)
	if err != nil {
		return diffArtifacts{}, err
	}

	patchOut, err := runHardenedGit(ctx, gitBin, env, workDir,
		"-c", "diff.renames=true",
		"-c", "diff.mnemonicPrefix=false",
		"-c", "core.quotepath=false",
		"diff", "--cached", "-M", "--binary", "--no-ext-diff", "--no-color", baseSHA, "--",
	)
	if err != nil {
		return diffArtifacts{}, err
	}

	return diffArtifacts{
		TreeDigest:   treeDigest,
		ChangedFiles: changedFiles,
		UnifiedDiff:  string(patchOut),
		DiffDigest:   domain.SHA256Hex(patchOut),
	}, nil
}

func parseNameStatusZ(raw []byte) ([]rawGitChange, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}

	out := make([]rawGitChange, 0, len(parts)/2)
	for i := 0; i < len(parts); {
		status := string(parts[i])
		i++
		if status == "" {
			return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "empty status token in git diff output")
		}
		switch status[0] {
		case 'A':
			if i >= len(parts) {
				return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "truncated added path in git diff output")
			}
			out = append(out, rawGitChange{ChangeType: "ADDED", Path: string(parts[i])})
			i++
		case 'M', 'T':
			if i >= len(parts) {
				return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "truncated modified path in git diff output")
			}
			out = append(out, rawGitChange{ChangeType: "MODIFIED", Path: string(parts[i])})
			i++
		case 'D':
			if i >= len(parts) {
				return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "truncated deleted path in git diff output")
			}
			out = append(out, rawGitChange{ChangeType: "DELETED", Path: string(parts[i])})
			i++
		case 'R':
			if i+1 >= len(parts) {
				return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "truncated renamed paths in git diff output")
			}
			out = append(out, rawGitChange{
				ChangeType: "RENAMED",
				OldPath:    string(parts[i]),
				Path:       string(parts[i+1]),
			})
			i += 2
		case 'C':
			if i+1 >= len(parts) {
				return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", "truncated copied paths in git diff output")
			}
			out = append(out, rawGitChange{
				ChangeType: "ADDED",
				Path:       string(parts[i+1]),
			})
			i += 2
		default:
			return nil, domain.Internal("GIT_DIFF_PARSE_FAILED", fmt.Sprintf("unsupported git diff status %q", status))
		}
	}
	return out, nil
}

func enrichChangedFiles(workDir string, raw []rawGitChange) ([]ChangedFile, error) {
	if len(raw) == 0 {
		return []ChangedFile{}, nil
	}
	root, err := os.OpenRoot(workDir)
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "RECONSTRUCT_ROOT_FAILED", "failed opening working tree root", err)
	}
	defer root.Close()

	changes := make([]ChangedFile, 0, len(raw))
	for _, rc := range raw {
		cleanPath, err := archive.ValidateArchiveRelPath(rc.Path)
		if err != nil {
			return nil, err
		}
		cleanOld := ""
		if rc.OldPath != "" {
			cleanOld, err = archive.ValidateArchiveRelPath(rc.OldPath)
			if err != nil {
				return nil, err
			}
		}

		if rc.ChangeType == "DELETED" {
			changes = append(changes, ChangedFile{
				Path:       cleanPath,
				ChangeType: "DELETED",
				SizeBytes:  0,
			})
			continue
		}

		sizeBytes, fileSHA, err := statAndHashRegularFile(root, cleanPath)
		if err != nil {
			return nil, err
		}
		changes = append(changes, ChangedFile{
			Path:       cleanPath,
			ChangeType: rc.ChangeType,
			OldPath:    cleanOld,
			SizeBytes:  sizeBytes,
			SHA256:     fileSHA,
		})
	}

	slices.SortFunc(changes, func(a, b ChangedFile) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		if c := strings.Compare(a.ChangeType, b.ChangeType); c != 0 {
			return c
		}
		return strings.Compare(a.OldPath, b.OldPath)
	})
	return changes, nil
}

func statAndHashRegularFile(root *os.Root, relPath string) (int64, string, error) {
	f, err := root.OpenFile(relPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, "", domain.WrapError(domain.ErrUnprocessable, "RECONSTRUCT_FILE_ERROR", "failed reading reconstructed file", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, "", domain.WrapError(domain.ErrUnprocessable, "RECONSTRUCT_FILE_ERROR", "failed inspecting reconstructed file", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, "", domain.Unprocessable("UNSAFE_FILE_TYPE", "reconstructed file must be a regular file")
	}

	fileSHA, n, err := domain.SHA256Reader(f)
	if err != nil {
		return 0, "", domain.WrapError(domain.ErrUnprocessable, "RECONSTRUCT_FILE_ERROR", "failed hashing reconstructed file", err)
	}
	if n != info.Size() {
		return 0, "", domain.Unprocessable("RECONSTRUCT_FILE_ERROR", "reconstructed file size changed during hashing")
	}
	return n, fileSHA, nil
}
