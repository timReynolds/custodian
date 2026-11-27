package quarantine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
)

var defaultAllowedRefPrefixes = []string{"refs/heads/", "refs/tags/"}

// NewQuarantineUnpacker constructs a QuarantineUnpacker with validated configuration and defaults.
func NewQuarantineUnpacker(cfg UnpackerConfig) (*QuarantineUnpacker, error) {
	if cfg.Timeout < 0 {
		return nil, domain.BadRequest("INVALID_UNPACKER_CONFIG", "timeout must not be negative")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	gitBin := strings.TrimSpace(cfg.GitBinary)
	if gitBin == "" {
		gitBin = defaultGitBinary
	}

	resolvedLimits, err := cfg.DefaultLimits.resolve(defaultLimits())
	if err != nil {
		return nil, err
	}

	var prefixes []string
	if len(cfg.AllowedRefPrefixes) == 0 {
		prefixes = append([]string(nil), defaultAllowedRefPrefixes...)
	} else {
		prefixes = make([]string, 0, len(cfg.AllowedRefPrefixes))
		for _, p := range cfg.AllowedRefPrefixes {
			trimmed := strings.TrimSpace(p)
			if trimmed == "" || !strings.HasPrefix(trimmed, "refs/") || !strings.HasSuffix(trimmed, "/") {
				return nil, domain.BadRequest("INVALID_UNPACKER_CONFIG", fmt.Sprintf("allowed ref prefix %q must start with refs/ and end with /", p))
			}
			for _, dis := range disallowedRefPrefixes {
				if strings.HasPrefix(trimmed, dis) || strings.HasPrefix(dis, trimmed) && trimmed == "refs/" {
					return nil, domain.BadRequest("INVALID_UNPACKER_CONFIG", fmt.Sprintf("allowed ref prefix %q overlaps disallowed namespace", p))
				}
			}
			prefixes = append(prefixes, trimmed)
		}
	}

	return &QuarantineUnpacker{
		gitBinary:           gitBin,
		timeout:             timeout,
		allowedRefPrefixes:  prefixes,
		defaultLimits:       resolvedLimits,
		snapshotStore:       cfg.SnapshotStore,
		allowTagToNonCommit: cfg.AllowTagToNonCommit,
		metrics:             cfg.Metrics,
		logger:              cfg.Logger,
	}, nil
}

// Unpack validates ref updates, spools and scans the packfile within strict bounds,
// unpacks into an isolated quarantine repository, rejects unsafe objects/paths/unreferenced blobs,
// extracts history into a safe inspection workspace, computes push_manifest_digest, and builds GIT_PUSH_BUNDLE.
func (u *QuarantineUnpacker) Unpack(ctx context.Context, req UnpackRequest) (*UnpackResult, error) {
	if u == nil {
		return nil, domain.Internal("NIL_UNPACKER", "quarantine unpacker must not be nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if u.timeout > 0 {
		var cancel context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			ctx, cancel = context.WithTimeout(ctx, u.timeout)
			defer cancel()
		}
	}

	startedAt := time.Now()
	limits, err := req.Limits.resolve(u.defaultLimits)
	if err != nil {
		u.recordRejection("invalid_limits", req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	// Phase 1A: Pre-pack RefUpdate validation (zero pack bytes read).
	normalizedRefs, hasNonZeroNewOID, err := u.validateRefUpdatesPrePack(ctx, req.RefUpdates, req.ExistingRefResolver, limits)
	if err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	packReader := req.PackReader
	if packReader == nil {
		if hasNonZeroNewOID {
			err := domain.BadRequest("MISSING_PACK_READER", "pack reader must not be nil")
			u.recordRejection("missing_pack_reader", req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
		packReader = bytes.NewReader(nil)
	}

	// Create ephemeral 0700 quarantine root, homeDir, xdgDir, quar.git, and 0755 workspace.
	quarantineRoot, err := os.MkdirTemp("", "custodian-quarantine-*")
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_MKDIR_FAILED", "failed creating quarantine temp dir", err)
	}
	if err := os.Chmod(quarantineRoot, 0o700); err != nil {
		_ = os.RemoveAll(quarantineRoot)
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_CHMOD_FAILED", "failed securing quarantine dir permissions", err)
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(quarantineRoot)
		}
	}()

	homeDir := filepath.Join(quarantineRoot, "home")
	xdgDir := filepath.Join(homeDir, "xdg")
	quarRepo := filepath.Join(quarantineRoot, "quar.git")
	workspaceDir := filepath.Join(quarantineRoot, "workspace")
	for _, dirSpec := range []struct {
		path string
		mode os.FileMode
	}{
		{homeDir, 0o700},
		{xdgDir, 0o700},
		{workspaceDir, 0o755},
	} {
		if err := os.MkdirAll(dirSpec.path, dirSpec.mode); err != nil {
			return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_MKDIR_FAILED", "failed creating quarantine subdir", err)
		}
		if err := os.Chmod(dirSpec.path, dirSpec.mode); err != nil {
			return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_CHMOD_FAILED", "failed setting quarantine subdir permissions", err)
		}
	}

	// Phase 1B: git check-ref-format (without --allow-onelevel) before reading any pack bytes.
	// validateRefSyntax + validateAllowedRefNamespace already guarantee ru.RefName cannot start with '-'.
	for _, ru := range normalizedRefs {
		if _, err := runHardenedGit(ctx, u.gitBinary, homeDir, "", nil, "check-ref-format", ru.RefName); err != nil {
			domErr := domain.Unprocessable("INVALID_REF_NAME", fmt.Sprintf("ref %q failed git check-ref-format", ru.RefName))
			u.recordRejection("invalid_ref_name", req.PushSessionID, domErr.Code())
			return nil, domErr
		}
	}

	// Validate optional baseline directories before touching pack bytes.
	baselineRepoDir, baselineObjectsDir, err := resolveBaselineDirs(req.BaselineRepoDir, req.ExistingObjectsDir)
	if err != nil {
		u.recordRejection("invalid_baseline_dir", req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	// Collect trusted baseline candidates & enforce fail-closed non-zero OldOID verification
	// before reading or indexing any untrusted pack bytes.
	trustedCandidates, err := collectTrustedExcludeCandidates(ctx, u.gitBinary, homeDir, baselineRepoDir, baselineObjectsDir, normalizedRefs, req.ExistingRefResolver, req.BaselineOIDs)
	if err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	// Phase 2: Bounded streaming spool + SHA-1 checksum check.
	incomingPackPath := filepath.Join(quarantineRoot, "incoming.pack")
	totalPackBytes, _, _, err := spoolPack(ctx, packReader, incomingPackPath, limits.MaxPackBytes)
	if err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	// Phase 3: Go Packfile v2 Streaming Pre-Scanner (zip/delta bomb protection).
	var scanSummary packScanSummary
	if totalPackBytes >= minPackBytes {
		scanSummary, err = scanPackFile(ctx, incomingPackPath, totalPackBytes, limits)
		if err != nil {
			u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	// Phase 4: Isolated bare quar.git init + alternates + pre-index baseline verification + git index-pack --strict.
	if _, err := runHardenedGit(ctx, u.gitBinary, homeDir, "", nil, "init", "--bare", "--initial-branch=main", "--", quarRepo); err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_INIT_FAILED", "failed initializing quarantine git repository", err)
	}
	if baselineObjectsDir != "" {
		alternatesPath := filepath.Join(quarRepo, "objects", "info", "alternates")
		if err := os.MkdirAll(filepath.Dir(alternatesPath), 0o700); err != nil {
			return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_ALTERNATES_FAILED", "failed creating quarantine info dir", err)
		}
		if err := os.WriteFile(alternatesPath, []byte(baselineObjectsDir+"\n"), 0o600); err != nil {
			return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_ALTERNATES_FAILED", "failed writing quarantine alternates file", err)
		}
	}

	// Verify baseline exclude OIDs against quarRepo BEFORE indexAndVerifyPack adds any untrusted pack objects.
	excludeOIDs := []string{}
	if baselineObjectsDir != "" && len(trustedCandidates) > 0 {
		excludeOIDs, err = verifyBaselineExcludesPreIndex(ctx, u.gitBinary, homeDir, quarRepo, normalizedRefs, trustedCandidates)
		if err != nil {
			u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	var incomingOIDs []string
	if totalPackBytes == 0 {
		if hasNonZeroNewOID {
			if baselineObjectsDir == "" {
				err := domain.Unprocessable("MALFORMED_PACK", "empty packfile is only permitted for pure deletions or baseline-existing targets")
				u.recordRejection("malformed_pack", req.PushSessionID, err.Code())
				return nil, err
			}
			// Verify all non-zero NewOIDs already exist in baseline objects.
			nonZeroTargets := collectUniqueNonZeroNewOIDs(normalizedRefs)
			present, err := batchCheckExist(ctx, u.gitBinary, homeDir, quarRepo, nonZeroTargets)
			if err != nil {
				return nil, err
			}
			for _, oid := range nonZeroTargets {
				if _, ok := present[oid]; !ok {
					err := domain.Unprocessable("MALFORMED_PACK", fmt.Sprintf("empty packfile missing target object %s in baseline", oid))
					u.recordRejection("malformed_pack", req.PushSessionID, err.Code())
					return nil, err
				}
			}
		}
	} else {
		incomingOIDs, err = u.indexAndVerifyPack(ctx, homeDir, quarRepo, incomingPackPath, totalPackBytes, baselineObjectsDir != "", scanSummary.NumObjects, limits)
		if err != nil {
			u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	// Phase 5: Target type verification, quarantine ref updates, fsck, and unreferenced object rejection.
	if err := u.verifyRefTargetsAndFsck(ctx, homeDir, quarRepo, normalizedRefs, limits); err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	if baselineObjectsDir == "" && len(trustedCandidates) > 0 {
		// Without an attached baseline object store, filter only already-trusted candidates
		// (resolver-verified or static BaselineOIDs) to OIDs present in quarRepo for git rev-list.
		excludeOIDs, err = filterExistingOIDs(ctx, u.gitBinary, homeDir, quarRepo, trustedCandidates)
		if err != nil {
			u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	if len(incomingOIDs) > 0 {
		if err := verifyNoUnreferencedObjects(ctx, u.gitBinary, homeDir, quarRepo, normalizedRefs, incomingOIDs, excludeOIDs); err != nil {
			u.recordRejection("unreferenced_object", req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	// Phase 6: Exhaustive tree & path hardening across ALL newly introduced trees & commits.
	if hasNonZeroNewOID {
		if err := verifyIntroducedTreesAndPaths(ctx, u.gitBinary, homeDir, quarRepo, normalizedRefs, excludeOIDs, limits); err != nil {
			u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
			return nil, err
		}
	}

	// Phase 7: History extraction & safe workspace materialization (no git checkout).
	historyRes, err := extractAndMaterializeHistory(ctx, u.gitBinary, homeDir, quarRepo, workspaceDir, normalizedRefs, excludeOIDs, limits)
	if err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	// Phase 8: Content-pure PushManifest & push_manifest_digest.
	manifest, manifestJSON, manifestDigest, err := buildPushManifest(normalizedRefs, historyRes, req.LFSObjects)
	if err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	res := &UnpackResult{
		WorkspaceDir:       workspaceDir,
		RepoDir:            quarRepo,
		RefUpdates:         normalizedRefs,
		Commits:            historyRes.commits,
		Trees:              historyRes.trees,
		Blobs:              historyRes.blobs,
		Tags:               historyRes.tags,
		ChangedPaths:       historyRes.changedPaths,
		CommitMessages:     historyRes.commitMessages,
		LFSObjects:         normalizeLFSObjects(req.LFSObjects),
		PushManifestDigest: manifestDigest,
		Manifest:           manifest,
		quarantineRoot:     quarantineRoot,
		homeDir:            homeDir,
		gitBinary:          u.gitBinary,
		timeout:            u.timeout,
		excludeOIDs:        excludeOIDs,
	}

	// Phase 9: Deterministic GIT_PUSH_BUNDLE + optional SnapshotStore persistence.
	store := req.SnapshotStore
	if store == nil {
		store = u.snapshotStore
	}
	if err := buildAndStoreBundle(ctx, res, manifestJSON, manifestDigest, store); err != nil {
		u.recordRejection(rejectionReasonFromErr(err), req.PushSessionID, errorCodeOf(err))
		return nil, err
	}

	succeeded = true

	if u.metrics != nil {
		u.metrics.ObservePushPhase("quarantine", "internal", "unpack", time.Since(startedAt))
	}
	if u.logger != nil {
		u.logger.Info("quarantine unpack completed",
			slog.String("component", "quarantine"),
			slog.String("push_session_id", req.PushSessionID.String()),
			slog.String("push_manifest_digest", res.PushManifestDigest),
			slog.Int("ref_count", len(res.RefUpdates)),
			slog.Int("commit_count", len(res.Commits)),
			slog.Int("object_count", len(res.Commits)+len(res.Trees)+len(res.Blobs)+len(res.Tags)),
			slog.Int64("pack_bytes", totalPackBytes),
			slog.Int64("duration_ms", time.Since(startedAt).Milliseconds()),
		)
	}
	return res, nil
}

func (u *QuarantineUnpacker) validateRefUpdatesPrePack(
	ctx context.Context,
	refs []RefUpdate,
	resolver ExistingRefResolver,
	limits Limits,
) ([]RefUpdate, bool, error) {
	if len(refs) == 0 {
		return nil, false, domain.BadRequest("EMPTY_REF_UPDATES", "at least one ref update is required")
	}
	if len(refs) > limits.MaxRefUpdates {
		return nil, false, domain.Unprocessable("REF_UPDATES_LIMIT_EXCEEDED", fmt.Sprintf("ref update count %d exceeds max_ref_updates %d", len(refs), limits.MaxRefUpdates))
	}

	seen := make(map[string]struct{}, len(refs))
	normalized := make([]RefUpdate, 0, len(refs))
	hasNonZeroNewOID := false

	for _, ru := range refs {
		if err := validateRefSyntax(ru.RefName); err != nil {
			return nil, false, err
		}
		if err := validateAllowedRefNamespace(ru.RefName, u.allowedRefPrefixes); err != nil {
			return nil, false, err
		}
		if _, dup := seen[ru.RefName]; dup {
			return nil, false, domain.BadRequest("DUPLICATE_REF_UPDATE", fmt.Sprintf("duplicate ref update for %q", ru.RefName))
		}
		seen[ru.RefName] = struct{}{}

		oldOID, err := domain.ParseGitSHA(ru.OldOID)
		if err != nil {
			return nil, false, domain.BadRequest("INVALID_GIT_SHA", fmt.Sprintf("invalid old_oid for %q", ru.RefName))
		}
		newOID, err := domain.ParseGitSHA(ru.NewOID)
		if err != nil {
			return nil, false, domain.BadRequest("INVALID_GIT_SHA", fmt.Sprintf("invalid new_oid for %q", ru.RefName))
		}
		if oldOID == ZeroOID && newOID == ZeroOID {
			return nil, false, domain.BadRequest("INVALID_REF_UPDATE", fmt.Sprintf("ref update %q has zero old_oid and zero new_oid", ru.RefName))
		}
		if newOID != ZeroOID {
			hasNonZeroNewOID = true
		}

		if resolver != nil {
			resolvedOID, exists, err := resolver.ResolveRef(ctx, ru.RefName)
			if err != nil {
				return nil, false, domain.WrapError(domain.ErrUnavailable, "REF_RESOLVE_FAILED", "failed resolving existing upstream ref", err)
			}
			expectedOld := ZeroOID
			if exists {
				expectedOld, err = domain.ParseGitSHA(resolvedOID)
				if err != nil {
					return nil, false, domain.WrapError(domain.ErrInternal, "INVALID_UPSTREAM_REF_OID", "resolved upstream ref OID is invalid", err)
				}
			}
			if oldOID != expectedOld {
				return nil, false, domain.Conflict("REF_CAS_MISMATCH", fmt.Sprintf("old_oid %s does not match current upstream oid %s for %q", oldOID, expectedOld, ru.RefName))
			}
		}

		normalized = append(normalized, RefUpdate{
			RefName: ru.RefName,
			OldOID:  oldOID,
			NewOID:  newOID,
		})
	}

	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].RefName != normalized[j].RefName {
			return normalized[i].RefName < normalized[j].RefName
		}
		if normalized[i].OldOID != normalized[j].OldOID {
			return normalized[i].OldOID < normalized[j].OldOID
		}
		return normalized[i].NewOID < normalized[j].NewOID
	})

	return normalized, hasNonZeroNewOID, nil
}

func validateNonSymlinkDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", domain.BadRequest("INVALID_BASELINE_DIR", "invalid baseline directory path")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", domain.BadRequest("INVALID_BASELINE_DIR", "baseline directory does not exist")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", domain.Unprocessable("UNSAFE_BASELINE_DIR", "baseline directory must not be a symlink")
	}
	if !info.IsDir() {
		return "", domain.BadRequest("INVALID_BASELINE_DIR", "baseline path is not a directory")
	}
	return abs, nil
}

func resolveBaselineDirs(baselineRepoDir, existingObjectsDir string) (repoDir, objectsDir string, err error) {
	if strings.TrimSpace(baselineRepoDir) != "" {
		repoDir, err = validateNonSymlinkDir(baselineRepoDir)
		if err != nil {
			return "", "", err
		}
	}
	if strings.TrimSpace(existingObjectsDir) != "" {
		objectsDir, err = validateNonSymlinkDir(existingObjectsDir)
		if err != nil {
			return "", "", err
		}
		return repoDir, objectsDir, nil
	}
	if repoDir != "" {
		cand := filepath.Join(repoDir, "objects")
		if _, statErr := os.Lstat(cand); statErr == nil {
			objectsDir, err = validateNonSymlinkDir(cand)
			if err != nil {
				return "", "", err
			}
			return repoDir, objectsDir, nil
		}
		dotGitObj := filepath.Join(repoDir, ".git", "objects")
		objectsDir, err = validateNonSymlinkDir(dotGitObj)
		if err != nil {
			return "", "", err
		}
		return repoDir, objectsDir, nil
	}
	return "", "", nil
}

func (u *QuarantineUnpacker) indexAndVerifyPack(
	ctx context.Context,
	homeDir, quarRepo, incomingPackPath string,
	totalPackBytes int64,
	hasBaseline bool,
	expectedNumObjects uint32,
	limits Limits,
) ([]string, error) {
	packFile, err := os.Open(incomingPackPath)
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_PACK_OPEN_FAILED", "failed opening packfile for index-pack", err)
	}
	defer packFile.Close()

	args := []string{
		"index-pack",
		indexPackStrictFlag,
		fmt.Sprintf("--max-input-size=%d", limits.MaxPackBytes),
	}
	if hasBaseline {
		args = append(args, "--fix-thin")
	}
	args = append(args, "--stdin")

	if _, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, packFile, args...); err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "unresolved delta") {
			return nil, domain.Unprocessable("UNRESOLVED_THIN_DELTA", "thin pack references missing delta base object")
		}
		return nil, domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("packfile rejected by git index-pack --strict: %s", checkout.SanitizeGitOutput(err.Error())))
	}

	idxMatches, err := filepath.Glob(filepath.Join(quarRepo, "objects", "pack", "*.idx"))
	if err != nil || len(idxMatches) != 1 {
		return nil, domain.Unprocessable("PACK_FSCK_FAILED", "expected exactly one pack index file after index-pack")
	}

	verifyOut, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, nil, "verify-pack", "-v", "--", idxMatches[0])
	if err != nil {
		return nil, domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("packfile rejected by git verify-pack: %s", checkout.SanitizeGitOutput(err.Error())))
	}
	if err := verifyPackDeltaDepth(verifyOut, limits.MaxDeltaDepth); err != nil {
		return nil, err
	}

	idxFile, err := os.Open(idxMatches[0])
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_INDEX_OPEN_FAILED", "failed opening pack index", err)
	}
	defer idxFile.Close()

	showIdxOut, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, idxFile, "show-index")
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "QUARANTINE_SHOW_INDEX_FAILED", "failed reading pack index", err)
	}

	origBodyEnd := totalPackBytes - packTrailerSize
	incomingOIDs := make([]string, 0, expectedNumObjects)
	for _, line := range strings.Split(strings.TrimSpace(string(showIdxOut)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, domain.Unprocessable("MALFORMED_PACK", "malformed git show-index line")
		}
		offset, perr := strconv.ParseInt(fields[0], 10, 64)
		if perr != nil {
			return nil, domain.Unprocessable("MALFORMED_PACK", "invalid pack index offset")
		}
		oid, oerr := domain.ParseGitSHA(fields[1])
		if oerr != nil {
			return nil, domain.Unprocessable("MALFORMED_PACK", "invalid pack index OID")
		}
		if offset < origBodyEnd {
			incomingOIDs = append(incomingOIDs, oid)
		}
	}

	if len(incomingOIDs) != int(expectedNumObjects) {
		return nil, domain.Unprocessable("MALFORMED_PACK", fmt.Sprintf("pack object count mismatch: header=%d indexed=%d", expectedNumObjects, len(incomingOIDs)))
	}

	if len(incomingOIDs) > 0 {
		metaMap, err := batchCheckObjects(ctx, u.gitBinary, homeDir, quarRepo, incomingOIDs)
		if err != nil {
			return nil, err
		}
		for _, oid := range incomingOIDs {
			meta, ok := metaMap[oid]
			if !ok {
				return nil, domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("indexed object %s missing in quarantine store", oid))
			}
			if meta.size > limits.MaxInflatedObjectBytes {
				return nil, domain.Unprocessable("INFLATED_OBJECT_LIMIT_EXCEEDED", fmt.Sprintf("object %s size %d exceeds max_inflated_object_bytes %d", oid, meta.size, limits.MaxInflatedObjectBytes))
			}
		}
	}

	sort.Strings(incomingOIDs)
	return incomingOIDs, nil
}

func verifyPackDeltaDepth(verifyOut []byte, maxDeltaDepth int) error {
	for _, rawLine := range strings.Split(string(verifyOut), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		oid, err := domain.ParseGitSHA(fields[0])
		if err != nil {
			// Ignore summary/status lines such as "non delta: ...", "chain length = ...", "<pack>: ok".
			continue
		}
		switch fields[1] {
		case "commit", "tree", "blob", "tag":
		default:
			continue
		}
		depth, err := strconv.Atoi(fields[5])
		if err != nil || depth < 1 {
			return domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("invalid delta depth %q for pack object %s", fields[5], oid))
		}
		if depth > maxDeltaDepth {
			return domain.Unprocessable(
				"DELTA_DEPTH_LIMIT_EXCEEDED",
				fmt.Sprintf("pack object %s delta chain depth %d exceeds max_delta_depth %d", oid, depth, maxDeltaDepth),
			)
		}
	}
	return nil
}

type gitObjMeta struct {
	objType string
	size    int64
}

func batchCheckObjects(ctx context.Context, gitBin, homeDir, repoDir string, oids []string) (map[string]gitObjMeta, error) {
	out := make(map[string]gitObjMeta, len(oids))
	if len(oids) == 0 {
		return out, nil
	}
	var stdinBuf bytes.Buffer
	for _, oid := range oids {
		stdinBuf.WriteString(oid)
		stdinBuf.WriteByte('\n')
	}
	raw, err := runHardenedGit(ctx, gitBin, homeDir, repoDir, &stdinBuf, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if err != nil {
		return nil, domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed inspecting quarantine objects", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "missing" {
			continue
		}
		if len(fields) != 3 {
			return nil, domain.Unprocessable("PACK_FSCK_FAILED", "unexpected cat-file batch-check output")
		}
		sz, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, domain.Unprocessable("PACK_FSCK_FAILED", "invalid object size from cat-file")
		}
		out[fields[0]] = gitObjMeta{objType: fields[1], size: sz}
	}
	return out, nil
}

func batchCheckExist(ctx context.Context, gitBin, homeDir, repoDir string, oids []string) (map[string]struct{}, error) {
	meta, err := batchCheckObjects(ctx, gitBin, homeDir, repoDir, oids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(meta))
	for k := range meta {
		out[k] = struct{}{}
	}
	return out, nil
}

func (u *QuarantineUnpacker) verifyRefTargetsAndFsck(ctx context.Context, homeDir, quarRepo string, refs []RefUpdate, limits Limits) error {
	var updateRefStdin bytes.Buffer
	hasUpdates := false

	for _, ru := range refs {
		if ru.NewOID == ZeroOID {
			continue
		}
		hasUpdates = true
		if err := u.verifySingleRefTarget(ctx, homeDir, quarRepo, ru.RefName, ru.NewOID, limits.MaxTagDepth); err != nil {
			return err
		}
		updateRefStdin.WriteString("create ")
		updateRefStdin.WriteString(ru.RefName)
		updateRefStdin.WriteByte(0)
		updateRefStdin.WriteString(ru.NewOID)
		updateRefStdin.WriteByte(0)
	}

	if hasUpdates {
		if _, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, &updateRefStdin, "update-ref", "--stdin", "-z"); err != nil {
			return domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("failed updating quarantine refs: %s", checkout.SanitizeGitOutput(err.Error())))
		}
	}

	if _, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, nil, "fsck", "--strict", "--no-dangling", "--no-reflogs"); err != nil {
		return domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("git fsck --strict failed: %s", checkout.SanitizeGitOutput(err.Error())))
	}
	return nil
}

func (u *QuarantineUnpacker) verifySingleRefTarget(ctx context.Context, homeDir, quarRepo, refName, newOID string, maxTagDepth int) error {
	out, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, nil, "cat-file", "-t", "--", newOID)
	if err != nil {
		return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("target object %s for %q not found", newOID, refName))
	}
	objType := strings.TrimSpace(string(out))

	if strings.HasPrefix(refName, "refs/heads/") {
		if objType != "commit" {
			return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("branch %q must target a commit, got %s", refName, objType))
		}
		return nil
	}

	if objType == "commit" {
		return nil
	}
	if objType != "tag" {
		if !u.allowTagToNonCommit || !strings.HasPrefix(refName, "refs/tags/") {
			return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("ref %q must target a commit or annotated tag, got %s", refName, objType))
		}
		return nil
	}

	curOID := newOID
	for depth := 1; depth <= maxTagDepth; depth++ {
		rawTag, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, nil, "cat-file", "tag", "--", curOID)
		if err != nil {
			return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("failed reading annotated tag %s", curOID))
		}
		targetOID, targetType, err := parseAnnotatedTagTarget(rawTag)
		if err != nil {
			return err
		}
		actualOut, err := runHardenedGit(ctx, u.gitBinary, homeDir, quarRepo, nil, "cat-file", "-t", "--", targetOID)
		if err != nil || strings.TrimSpace(string(actualOut)) != targetType {
			return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("tag %s target %s type mismatch", curOID, targetOID))
		}
		if targetType == "commit" {
			return nil
		}
		if targetType == "tag" {
			if depth == maxTagDepth {
				return domain.Unprocessable("TAG_DEPTH_LIMIT_EXCEEDED", fmt.Sprintf("annotated tag chain for %q exceeds max_tag_depth %d", refName, maxTagDepth))
			}
			curOID = targetOID
			continue
		}
		if !u.allowTagToNonCommit || !strings.HasPrefix(refName, "refs/tags/") {
			return domain.Unprocessable("INVALID_REF_TARGET_TYPE", fmt.Sprintf("tag %q peels to %s rather than commit", refName, targetType))
		}
		return nil
	}
	return domain.Unprocessable("TAG_DEPTH_LIMIT_EXCEEDED", fmt.Sprintf("annotated tag chain for %q exceeded max_tag_depth", refName))
}

func parseAnnotatedTagTarget(raw []byte) (targetOID, targetType string, err error) {
	headerBytes := raw
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		headerBytes = raw[:idx]
	}
	for _, line := range strings.Split(string(headerBytes), "\n") {
		if strings.HasPrefix(line, "object ") {
			oid, perr := domain.ParseGitSHA(strings.TrimPrefix(line, "object "))
			if perr != nil {
				return "", "", domain.Unprocessable("INVALID_REF_TARGET_TYPE", "invalid object OID in annotated tag")
			}
			targetOID = oid
		} else if strings.HasPrefix(line, "type ") {
			targetType = strings.TrimSpace(strings.TrimPrefix(line, "type "))
		}
	}
	if targetOID == "" || targetType == "" {
		return "", "", domain.Unprocessable("INVALID_REF_TARGET_TYPE", "malformed annotated tag header")
	}
	return targetOID, targetType, nil
}

func collectUniqueNonZeroNewOIDs(refs []RefUpdate) []string {
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, ru := range refs {
		if ru.NewOID == "" || ru.NewOID == ZeroOID {
			continue
		}
		if _, ok := seen[ru.NewOID]; !ok {
			seen[ru.NewOID] = struct{}{}
			out = append(out, ru.NewOID)
		}
	}
	sort.Strings(out)
	return out
}

func collectTrustedExcludeCandidates(
	ctx context.Context,
	gitBin, homeDir, baselineRepoDir, baselineObjectsDir string,
	refs []RefUpdate,
	resolver ExistingRefResolver,
	staticBaselineOIDs []string,
) ([]string, error) {
	candidateSet := make(map[string]struct{})
	staticBaselineSet := make(map[string]struct{})

	for _, raw := range staticBaselineOIDs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		oid, err := domain.ParseGitSHA(raw)
		if err != nil {
			return nil, domain.BadRequest("INVALID_GIT_SHA", "invalid baseline OID")
		}
		if oid != ZeroOID {
			staticBaselineSet[oid] = struct{}{}
			candidateSet[oid] = struct{}{}
		}
	}

	if resolver != nil {
		list, err := resolver.ListBaselineOIDs(ctx)
		if err != nil {
			return nil, domain.WrapError(domain.ErrUnavailable, "BASELINE_RESOLVE_FAILED", "failed listing baseline OIDs", err)
		}
		for _, raw := range list {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			oid, err := domain.ParseGitSHA(raw)
			if err != nil {
				return nil, domain.BadRequest("INVALID_GIT_SHA", "invalid baseline OID from resolver")
			}
			if oid != ZeroOID {
				candidateSet[oid] = struct{}{}
			}
		}
	}

	if baselineObjectsDir == "" {
		if resolver == nil {
			for _, ru := range refs {
				if ru.OldOID != "" && ru.OldOID != ZeroOID {
					if _, ok := staticBaselineSet[ru.OldOID]; !ok {
						return nil, domain.Unprocessable("BASELINE_OBJECT_MISSING", fmt.Sprintf("old_oid %s is missing from baseline object store", ru.OldOID))
					}
				}
			}
		} else {
			// Resolver already verified CAS equality for each ru.OldOID in Phase 1A.
			for _, ru := range refs {
				if ru.OldOID != "" && ru.OldOID != ZeroOID {
					candidateSet[ru.OldOID] = struct{}{}
				}
			}
		}
	} else {
		for _, ru := range refs {
			if ru.OldOID != "" && ru.OldOID != ZeroOID {
				candidateSet[ru.OldOID] = struct{}{}
			}
		}
		if baselineRepoDir != "" {
			rawRefs, err := runHardenedGit(ctx, gitBin, homeDir, baselineRepoDir, nil, "for-each-ref", "--format=%(objectname)")
			if err != nil {
				return nil, domain.WrapError(domain.ErrUnprocessable, "BASELINE_REPO_ERROR", "failed reading baseline repository refs", err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(rawRefs)), "\n") {
				if line == "" {
					continue
				}
				oid, err := domain.ParseGitSHA(line)
				if err != nil {
					continue
				}
				if oid != ZeroOID {
					candidateSet[oid] = struct{}{}
				}
			}
		}
	}

	if len(candidateSet) == 0 {
		return nil, nil
	}

	candidates := make([]string, 0, len(candidateSet))
	for oid := range candidateSet {
		candidates = append(candidates, oid)
	}
	sort.Strings(candidates)
	return candidates, nil
}

func verifyBaselineExcludesPreIndex(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	refs []RefUpdate,
	candidates []string,
) ([]string, error) {
	if len(candidates) == 0 {
		return []string{}, nil
	}

	// quarRepo contains ONLY baselineObjectsDir via alternates (zero untrusted pack objects).
	existing, err := batchCheckExist(ctx, gitBin, homeDir, quarRepo, candidates)
	if err != nil {
		return nil, err
	}

	for _, ru := range refs {
		if ru.OldOID != "" && ru.OldOID != ZeroOID {
			if _, ok := existing[ru.OldOID]; !ok {
				return nil, domain.Unprocessable("BASELINE_OBJECT_MISSING", fmt.Sprintf("old_oid %s is missing from baseline object store", ru.OldOID))
			}
		}
	}

	excludeOIDs := make([]string, 0, len(existing))
	for oid := range existing {
		excludeOIDs = append(excludeOIDs, oid)
	}
	sort.Strings(excludeOIDs)
	return excludeOIDs, nil
}

func filterExistingOIDs(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	candidates []string,
) ([]string, error) {
	if len(candidates) == 0 {
		return []string{}, nil
	}
	existing, err := batchCheckExist(ctx, gitBin, homeDir, quarRepo, candidates)
	if err != nil {
		return nil, err
	}
	excludeOIDs := make([]string, 0, len(existing))
	for oid := range existing {
		excludeOIDs = append(excludeOIDs, oid)
	}
	sort.Strings(excludeOIDs)
	return excludeOIDs, nil
}

func verifyNoUnreferencedObjects(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	refs []RefUpdate,
	incomingOIDs []string,
	excludeOIDs []string,
) error {
	newOIDs := collectUniqueNonZeroNewOIDs(refs)
	if len(newOIDs) == 0 {
		return domain.Unprocessable("UNREFERENCED_OBJECT", "packfile contains objects on a pure deletion push")
	}

	fastReachable, err := runRevListObjects(ctx, gitBin, homeDir, quarRepo, newOIDs, excludeOIDs)
	if err != nil {
		return err
	}

	missing := make([]string, 0)
	for _, oid := range incomingOIDs {
		if _, ok := fastReachable[oid]; !ok {
			missing = append(missing, oid)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	// Fallback full reachability without --not exclusions handles pushes that re-send baseline objects.
	fullReachable, err := runRevListObjects(ctx, gitBin, homeDir, quarRepo, newOIDs, nil)
	if err != nil {
		return err
	}
	for _, oid := range missing {
		if _, ok := fullReachable[oid]; !ok {
			return domain.Unprocessable("UNREFERENCED_OBJECT", fmt.Sprintf("packfile contains unreferenced object %s", oid))
		}
	}
	return nil
}

func runRevListObjects(ctx context.Context, gitBin, homeDir, quarRepo string, includeOIDs, excludeOIDs []string) (map[string]string, error) {
	if len(includeOIDs) == 0 {
		return map[string]string{}, nil
	}
	var stdinBuf bytes.Buffer
	for _, oid := range includeOIDs {
		stdinBuf.WriteString(oid)
		stdinBuf.WriteByte('\n')
	}
	for _, ex := range excludeOIDs {
		stdinBuf.WriteByte('^')
		stdinBuf.WriteString(ex)
		stdinBuf.WriteByte('\n')
	}

	out, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, &stdinBuf, "rev-list", "--objects", "--stdin")
	if err != nil {
		return nil, domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed computing reachable objects", err)
	}
	res := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		oidPart, hint, _ := strings.Cut(line, " ")
		oid, perr := domain.ParseGitSHA(oidPart)
		if perr != nil {
			return nil, domain.Unprocessable("PACK_FSCK_FAILED", "invalid OID returned by git rev-list")
		}
		if prev, exists := res[oid]; !exists || (prev == "" && hint != "") {
			res[oid] = hint
		}
	}
	return res, nil
}

func verifyIntroducedTreesAndPaths(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	refs []RefUpdate,
	excludeOIDs []string,
	limits Limits,
) error {
	newOIDs := collectUniqueNonZeroNewOIDs(refs)
	if len(newOIDs) == 0 {
		return nil
	}

	// Collect newly introduced commits.
	var commitStdin bytes.Buffer
	for _, oid := range newOIDs {
		commitStdin.WriteString(oid)
		commitStdin.WriteByte('\n')
	}
	for _, ex := range excludeOIDs {
		commitStdin.WriteByte('^')
		commitStdin.WriteString(ex)
		commitStdin.WriteByte('\n')
	}
	commitsOut, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, &commitStdin, "rev-list", "--stdin")
	if err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed enumerating introduced commits", err)
	}

	newCommitOIDs := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(commitsOut)), "\n") {
		if line == "" {
			continue
		}
		oid, perr := domain.ParseGitSHA(line)
		if perr == nil {
			newCommitOIDs = append(newCommitOIDs, oid)
		}
	}

	// Collect all introduced tree OIDs from rev-list --objects plus tip commit trees.
	objs, err := runRevListObjects(ctx, gitBin, homeDir, quarRepo, newOIDs, excludeOIDs)
	if err != nil {
		return err
	}
	allOIDs := make([]string, 0, len(objs))
	for oid := range objs {
		allOIDs = append(allOIDs, oid)
	}
	meta, err := batchCheckObjects(ctx, gitBin, homeDir, quarRepo, allOIDs)
	if err != nil {
		return err
	}

	treeSet := make(map[string]struct{})
	for oid, m := range meta {
		if m.objType == "tree" {
			treeSet[oid] = struct{}{}
		}
	}

	// Also ensure each non-zero tip commit's root tree is checked.
	tipTrees := make([]string, 0, len(newOIDs))
	for _, oid := range newOIDs {
		out, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "rev-parse", "--verify", "--quiet", oid+"^{tree}")
		if err == nil {
			if treeOID, perr := domain.ParseGitSHA(strings.TrimSpace(string(out))); perr == nil {
				treeSet[treeOID] = struct{}{}
				tipTrees = append(tipTrees, treeOID)
			}
		}
	}

	treeList := make([]string, 0, len(treeSet))
	for oid := range treeSet {
		treeList = append(treeList, oid)
	}
	sort.Strings(treeList)

	// Inspect every newly introduced tree node directly.
	for _, treeOID := range treeList {
		raw, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "ls-tree", "-z", "--", treeOID)
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed inspecting tree object", err)
		}
		if err := validateSingleTreeEntries(raw); err != nil {
			return err
		}
	}

	// Inspect full recursive paths on tip trees (catches path depth/length and full-path collisions).
	for _, tipTree := range tipTrees {
		raw, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "ls-tree", "-r", "-t", "-z", "--", tipTree)
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed inspecting recursive tip tree", err)
		}
		if err := validateRecursiveTreeOutput(raw, limits); err != nil {
			return err
		}
	}

	// Inspect full paths across every newly introduced commit's diff-tree (catches historical depth/mode/segment evasions).
	for _, commitOID := range newCommitOIDs {
		raw, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "diff-tree", "--no-commit-id", "--raw", "-r", "-t", "-m", "--root", "-z", commitOID, "--")
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "PACK_FSCK_FAILED", "failed inspecting commit diff-tree", err)
		}
		if err := validateCommitDiffTreeRaw(raw, limits); err != nil {
			return err
		}
	}

	return nil
}

func validateTreeMode(mode string) error {
	switch mode {
	case "120000":
		return domain.Unprocessable("UNSAFE_SYMLINK", "symlink tree entries (120000) are not permitted")
	case "160000":
		return domain.Unprocessable("SUBMODULE_NOT_ALLOWED", "submodule gitlink entries (160000) are not permitted")
	case "100644", "100755", "040000", "40000":
		return nil
	default:
		return domain.Unprocessable("INVALID_TREE_MODE", fmt.Sprintf("disallowed git tree entry mode %q", mode))
	}
}

func validateTreeEntrySegment(seg string) error {
	if seg == "" || seg == "." || seg == ".." {
		return domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("unsafe tree entry name %q", seg))
	}
	if !utf8.ValidString(seg) {
		return domain.Unprocessable("UNSAFE_TREE_PATH", "tree entry name is not valid UTF-8")
	}
	if strings.ContainsRune(seg, '\x00') || strings.Contains(seg, "/") || strings.Contains(seg, "\\") {
		return domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("tree entry name %q contains illegal characters", seg))
	}
	if len(seg) >= 2 && seg[1] == ':' && ((seg[0] >= 'A' && seg[0] <= 'Z') || (seg[0] >= 'a' && seg[0] <= 'z')) {
		return domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("tree entry name %q contains drive prefix", seg))
	}
	for _, r := range seg {
		if r < 0x20 || r == 0x7f {
			return domain.Unprocessable("UNSAFE_TREE_PATH", "tree entry name contains control characters")
		}
	}
	stripped := stripIgnorableAndTrailing(seg)
	if strings.EqualFold(stripped, ".git") {
		return domain.Unprocessable("UNSAFE_TREE_PATH", "tree entry '.git' is not permitted")
	}
	if strings.EqualFold(stripped, ".gitmodules") {
		return domain.Unprocessable("SUBMODULE_NOT_ALLOWED", "tree entry '.gitmodules' is not permitted")
	}
	return nil
}

func validateSingleTreeEntries(raw []byte) error {
	tracker := newPathCollisionTracker()
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		metaPart, name, ok := strings.Cut(string(rec), "\t")
		if !ok {
			return domain.Unprocessable("MALFORMED_PACK", "malformed ls-tree record")
		}
		fields := strings.Fields(metaPart)
		if len(fields) != 3 {
			return domain.Unprocessable("MALFORMED_PACK", "malformed ls-tree metadata")
		}
		mode, objType := fields[0], fields[1]
		if err := validateTreeMode(mode); err != nil {
			return err
		}
		if err := validateTreeEntrySegment(name); err != nil {
			return err
		}
		isDir := objType == "tree"
		if err := tracker.add(name, isDir); err != nil {
			return err
		}
	}
	return nil
}

func validateFullTreeRelPath(rel string, limits Limits) (string, error) {
	if len(rel) > limits.MaxPathBytes {
		return "", domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("tree path exceeds max_path_bytes %d", limits.MaxPathBytes))
	}
	clean, err := archive.ValidateArchiveRelPath(rel)
	if err != nil {
		return "", domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("unsafe tree path %q", rel))
	}
	segs := strings.Split(clean, "/")
	if len(segs) > limits.MaxPathDepth {
		return "", domain.Unprocessable("UNSAFE_TREE_PATH", fmt.Sprintf("tree path depth %d exceeds max_path_depth %d", len(segs), limits.MaxPathDepth))
	}
	for _, seg := range segs {
		if err := validateTreeEntrySegment(seg); err != nil {
			return "", err
		}
	}
	return clean, nil
}

func validateRecursiveTreeOutput(raw []byte, limits Limits) error {
	tracker := newPathCollisionTracker()
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		metaPart, rawPath, ok := strings.Cut(string(rec), "\t")
		if !ok {
			return domain.Unprocessable("MALFORMED_PACK", "malformed recursive ls-tree record")
		}
		fields := strings.Fields(metaPart)
		if len(fields) != 3 {
			return domain.Unprocessable("MALFORMED_PACK", "malformed recursive ls-tree metadata")
		}
		mode, objType := fields[0], fields[1]
		if err := validateTreeMode(mode); err != nil {
			return err
		}
		clean, err := validateFullTreeRelPath(rawPath, limits)
		if err != nil {
			return err
		}
		if err := tracker.add(clean, objType == "tree"); err != nil {
			return err
		}
	}
	return nil
}

func validateCommitDiffTreeRaw(raw []byte, limits Limits) error {
	tokens := bytes.Split(raw, []byte{0})
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if len(tok) == 0 {
			continue
		}
		if tok[0] != ':' {
			continue
		}
		fields := strings.Fields(string(tok[1:]))
		if len(fields) < 5 {
			return domain.Unprocessable("MALFORMED_PACK", "malformed diff-tree raw header")
		}
		srcMode, dstMode, status := fields[0], fields[1], fields[4]
		if srcMode != "000000" {
			if err := validateTreeMode(srcMode); err != nil {
				return err
			}
		}
		if dstMode != "000000" {
			if err := validateTreeMode(dstMode); err != nil {
				return err
			}
		}
		if i+1 >= len(tokens) {
			return domain.Unprocessable("MALFORMED_PACK", "missing path in diff-tree output")
		}
		i++
		p1 := string(tokens[i])
		if _, err := validateFullTreeRelPath(p1, limits); err != nil {
			return err
		}
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i+1 >= len(tokens) {
				return domain.Unprocessable("MALFORMED_PACK", "missing destination path in diff-tree output")
			}
			i++
			p2 := string(tokens[i])
			if _, err := validateFullTreeRelPath(p2, limits); err != nil {
				return err
			}
		}
	}
	return nil
}

type trackedPathEntry struct {
	rawPath  string
	isDir    bool
	explicit bool
}

type pathCollisionTracker struct {
	caser   cases.Caser
	entries map[string]trackedPathEntry
}

func newPathCollisionTracker() *pathCollisionTracker {
	return &pathCollisionTracker{
		caser:   cases.Fold(),
		entries: make(map[string]trackedPathEntry),
	}
}

func (ct *pathCollisionTracker) foldSegment(seg string) string {
	stripped := stripIgnorableAndTrailing(seg)
	return norm.NFC.String(strings.ToLower(ct.caser.String(norm.NFD.String(stripped))))
}

func (ct *pathCollisionTracker) add(cleanPath string, isDir bool) error {
	segs := strings.Split(cleanPath, "/")
	foldedSegs := make([]string, len(segs))
	for i, seg := range segs {
		foldedSegs[i] = ct.foldSegment(seg)
	}

	for i := 0; i < len(segs)-1; i++ {
		rawPrefix := strings.Join(segs[:i+1], "/")
		foldedPrefix := strings.Join(foldedSegs[:i+1], "/")
		if prev, exists := ct.entries[foldedPrefix]; exists {
			if !prev.isDir {
				return domain.Unprocessable("PATH_COLLISION", fmt.Sprintf("file vs directory path collision on %q", rawPrefix))
			}
			if prev.rawPath != rawPrefix {
				return domain.Unprocessable("PATH_COLLISION", fmt.Sprintf("case or Unicode normalization collision on directory %q", rawPrefix))
			}
			continue
		}
		ct.entries[foldedPrefix] = trackedPathEntry{
			rawPath:  rawPrefix,
			isDir:    true,
			explicit: false,
		}
	}

	foldedFull := strings.Join(foldedSegs, "/")
	if prev, exists := ct.entries[foldedFull]; exists {
		if prev.explicit {
			return domain.Unprocessable("PATH_COLLISION", fmt.Sprintf("duplicate or colliding tree entry %q", cleanPath))
		}
		if !isDir {
			return domain.Unprocessable("PATH_COLLISION", fmt.Sprintf("file vs directory path collision on %q", cleanPath))
		}
		if prev.rawPath != cleanPath {
			return domain.Unprocessable("PATH_COLLISION", fmt.Sprintf("case or Unicode normalization collision on directory %q", cleanPath))
		}
		ct.entries[foldedFull] = trackedPathEntry{
			rawPath:  cleanPath,
			isDir:    true,
			explicit: true,
		}
		return nil
	}

	ct.entries[foldedFull] = trackedPathEntry{
		rawPath:  cleanPath,
		isDir:    isDir,
		explicit: true,
	}
	return nil
}

func rejectionReasonFromErr(err error) string {
	code := strings.ToLower(errorCodeOf(err))
	if code == "" {
		return "quarantine_error"
	}
	return code
}
