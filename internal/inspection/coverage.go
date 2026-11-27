package inspection

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

var stderrSkippedRe = regexp.MustCompile(`(?i)\bskipped\s+(\d+)\s+file(?:\(s\)|s)?(?:\s*:\s*([^\r\n]+))?`)

var knownManifestExact = map[string]struct{}{
	"go.mod":            {},
	"go.sum":            {},
	"package.json":      {},
	"package-lock.json": {},
	"yarn.lock":         {},
	"pnpm-lock.yaml":    {},
	"requirements.txt":  {},
	"pipfile.lock":      {},
	"poetry.lock":       {},
	"pyproject.toml":    {},
	"cargo.toml":        {},
	"cargo.lock":        {},
	"gemfile.lock":      {},
	"pom.xml":           {},
	"build.gradle":      {},
	"build.gradle.kts":  {},
	"composer.lock":     {},
	"dockerfile":        {},
}

// FileEntry represents a regular readable file discovered during workspace inventory.
type FileEntry struct {
	RelPath string
	AbsPath string
	Size    int64
}

// Inventory holds deterministic workspace file counts, skipped items, and manifest detections.
type Inventory struct {
	TargetDir      string
	Files          []FileEntry
	FilesExamined  int
	BytesExamined  int64
	FilesSkipped   int
	SkippedReasons []string
	ManifestPaths  []string
	HasManifests   bool
}

// WalkWorkspace inspects targetDir without following symlinks, recording readable regular files,
// unreadable/symlinked/special skipped files, and dependency/container manifests.
func WalkWorkspace(targetDir string) (*Inventory, error) {
	cleaned := filepath.Clean(targetDir)
	if cleaned == "" || cleaned == "." && targetDir == "" {
		return nil, domain.BadRequest("INVALID_TARGET_DIR", "target directory is required")
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_TARGET_DIR", "target directory cannot be accessed", err)
	}
	if !info.IsDir() {
		return nil, domain.BadRequest("INVALID_TARGET_DIR", "target path is not a directory")
	}

	inv := &Inventory{
		TargetDir:      cleaned,
		Files:          make([]FileEntry, 0, 16),
		SkippedReasons: make([]string, 0),
		ManifestPaths:  make([]string, 0),
	}

	err = filepath.WalkDir(cleaned, func(path string, d fs.DirEntry, walkErr error) error {
		rel, relErr := filepath.Rel(cleaned, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		rel = filepath.ToSlash(rel)

		if walkErr != nil {
			inv.FilesSkipped++
			inv.SkippedReasons = append(inv.SkippedReasons, fmt.Sprintf("unreadable:%s", rel))
			return nil
		}

		if d.IsDir() {
			if path != cleaned && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			inv.FilesSkipped++
			inv.SkippedReasons = append(inv.SkippedReasons, fmt.Sprintf("symlink_skipped:%s", rel))
			return nil
		}

		if !d.Type().IsRegular() {
			inv.FilesSkipped++
			inv.SkippedReasons = append(inv.SkippedReasons, fmt.Sprintf("non_regular_file:%s", rel))
			return nil
		}

		fInfo, statErr := d.Info()
		if statErr != nil {
			inv.FilesSkipped++
			inv.SkippedReasons = append(inv.SkippedReasons, fmt.Sprintf("stat_error:%s", rel))
			return nil
		}

		f, openErr := os.Open(path)
		if openErr != nil {
			inv.FilesSkipped++
			inv.SkippedReasons = append(inv.SkippedReasons, fmt.Sprintf("unreadable:%s", rel))
			return nil
		}
		_ = f.Close()

		inv.FilesExamined++
		inv.BytesExamined += fInfo.Size()
		inv.Files = append(inv.Files, FileEntry{
			RelPath: rel,
			AbsPath: path,
			Size:    fInfo.Size(),
		})
		if isManifestFile(rel) {
			inv.ManifestPaths = append(inv.ManifestPaths, rel)
			inv.HasManifests = true
		}
		return nil
	})
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "WORKSPACE_WALK_FAILED", "failed walking target workspace", err)
	}

	sort.Slice(inv.Files, func(i, j int) bool {
		return inv.Files[i].RelPath < inv.Files[j].RelPath
	})
	sort.Strings(inv.ManifestPaths)
	inv.SkippedReasons = dedupeNonEmptyStrings(inv.SkippedReasons)
	return inv, nil
}

func isManifestFile(relPath string) bool {
	base := strings.ToLower(filepath.Base(relPath))
	if _, ok := knownManifestExact[base]; ok {
		return true
	}
	if strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return true
	}
	if strings.HasSuffix(base, ".csproj") {
		return true
	}
	return false
}

func parseStderrSkipped(stderr string, redactor *Redactor) (int, []string) {
	if strings.TrimSpace(stderr) == "" {
		return 0, nil
	}
	total := 0
	var reasons []string
	matches := stderrSkippedRe.FindAllStringSubmatch(stderr, -1)
	for _, m := range matches {
		n := 0
		if len(m) >= 2 {
			if parsed, err := strconv.Atoi(m[1]); err == nil {
				n = parsed
			}
		}
		if n <= 0 {
			continue
		}
		total += n
		if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
			for _, part := range strings.Split(m[2], ",") {
				p := strings.TrimSpace(part)
				if redactor != nil {
					p = redactor.ScrubString(p)
				}
				if p != "" {
					reasons = append(reasons, "skipped:"+p)
				}
			}
		} else {
			reasons = append(reasons, "scanner_reported_skipped_files")
		}
	}
	return total, dedupeNonEmptyStrings(reasons)
}

func finalizeScanRunCoverage(
	run *domain.ScanRun,
	inv *Inventory,
	reportedExamined int,
	reportedSkipped int,
	reasons []string,
	crashed bool,
	timedOut bool,
	redactor *Redactor,
) {
	if run == nil {
		return
	}

	examined := reportedExamined
	var bytesExamined int64
	totalSkipped := reportedSkipped
	allReasons := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if redactor != nil {
			r = redactor.ScrubString(r)
		}
		if strings.TrimSpace(r) != "" {
			allReasons = append(allReasons, strings.TrimSpace(r))
		}
	}

	if inv != nil {
		bytesExamined = inv.BytesExamined
		if !crashed && !timedOut && inv.FilesExamined > examined {
			examined = inv.FilesExamined
		}
		if inv.FilesSkipped > 0 {
			totalSkipped += inv.FilesSkipped
			allReasons = append(allReasons, inv.SkippedReasons...)
		}
	}

	if examined < 0 {
		examined = 0
	}
	if totalSkipped < 0 {
		totalSkipped = 0
	}

	allReasons = dedupeNonEmptyStrings(allReasons)
	if allReasons == nil {
		allReasons = []string{}
	}

	run.Coverage = domain.ScanCoverage{
		FilesExamined:  examined,
		FilesSkipped:   totalSkipped,
		BytesExamined:  bytesExamined,
		SkippedReasons: allReasons,
	}

	switch {
	case timedOut:
		run.Status = domain.ScanStatusTimedOut
		run.Coverage.Complete = false
	case crashed:
		run.Status = domain.ScanStatusFailed
		run.Coverage.Complete = false
	case totalSkipped > 0 || len(allReasons) > 0:
		run.Status = domain.ScanStatusIncomplete
		run.Coverage.Complete = false
	default:
		run.Status = domain.ScanStatusCompleted
		run.Coverage.Complete = true
	}
}

func normalizeRelPath(targetDir, raw string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	cleanTarget := filepath.ToSlash(filepath.Clean(targetDir))
	if cleanTarget != "" && cleanTarget != "." {
		if strings.HasPrefix(p, cleanTarget+"/") {
			p = strings.TrimPrefix(p, cleanTarget+"/")
		} else if p == cleanTarget {
			p = "."
		}
	}
	p = strings.TrimPrefix(p, "./")
	return p
}

func dedupeNonEmptyStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
