package quarantine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
)

type historyExtractResult struct {
	commits        []ExtractedCommit
	trees          []string
	blobs          []ExtractedBlob
	tags           []ExtractedTag
	changedPaths   []string
	commitMessages []string
}

type blobWriteTarget struct {
	blobOID string
	relPath string
	size    int64
}

func extractAndMaterializeHistory(
	ctx context.Context,
	gitBin, homeDir, quarRepo, workspaceDir string,
	refs []RefUpdate,
	excludeOIDs []string,
	limits Limits,
) (historyExtractResult, error) {
	newOIDs := collectUniqueNonZeroNewOIDs(refs)
	if len(newOIDs) == 0 {
		return historyExtractResult{
			commits:        []ExtractedCommit{},
			trees:          []string{},
			blobs:          []ExtractedBlob{},
			tags:           []ExtractedTag{},
			changedPaths:   []string{},
			commitMessages: []string{},
		}, nil
	}

	introducedHints, err := runRevListObjects(ctx, gitBin, homeDir, quarRepo, newOIDs, excludeOIDs)
	if err != nil {
		return historyExtractResult{}, err
	}
	if len(introducedHints) > limits.MaxObjects {
		return historyExtractResult{}, domain.Unprocessable(
			"OBJECT_COUNT_LIMIT_EXCEEDED",
			fmt.Sprintf("introduced object count %d exceeds max_objects %d", len(introducedHints), limits.MaxObjects),
		)
	}

	allOIDs := make([]string, 0, len(introducedHints))
	for oid := range introducedHints {
		allOIDs = append(allOIDs, oid)
	}
	sort.Strings(allOIDs)

	metaMap, err := batchCheckObjects(ctx, gitBin, homeDir, quarRepo, allOIDs)
	if err != nil {
		return historyExtractResult{}, err
	}

	var (
		commitOIDs    []string
		treeOIDs      []string
		blobOIDs      []string
		tagOIDs       []string
		totalInflated int64
	)
	for _, oid := range allOIDs {
		m, ok := metaMap[oid]
		if !ok {
			return historyExtractResult{}, domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("introduced object %s missing in quarantine", oid))
		}
		if m.size > limits.MaxInflatedObjectBytes {
			return historyExtractResult{}, domain.Unprocessable("INFLATED_OBJECT_LIMIT_EXCEEDED", fmt.Sprintf("object %s exceeds max_inflated_object_bytes", oid))
		}
		if totalInflated > limits.MaxTotalInflatedBytes-m.size {
			return historyExtractResult{}, domain.Unprocessable("TOTAL_INFLATED_LIMIT_EXCEEDED", "introduced objects exceed max_total_inflated_bytes")
		}
		totalInflated += m.size

		switch m.objType {
		case "commit":
			commitOIDs = append(commitOIDs, oid)
		case "tree":
			treeOIDs = append(treeOIDs, oid)
		case "blob":
			blobOIDs = append(blobOIDs, oid)
		case "tag":
			tagOIDs = append(tagOIDs, oid)
		default:
			return historyExtractResult{}, domain.Unprocessable("PACK_FSCK_FAILED", fmt.Sprintf("unexpected object type %q for %s", m.objType, oid))
		}
	}

	commits, tags, err := extractCommitsAndTags(ctx, gitBin, homeDir, quarRepo, commitOIDs, tagOIDs)
	if err != nil {
		return historyExtractResult{}, err
	}

	commitMessages := make([]string, 0, len(commits))
	for _, c := range commits {
		commitMessages = append(commitMessages, c.Message)
	}

	changedPathSet := make(map[string]struct{})
	blobPathSets := make(map[string]map[string]struct{})
	for _, bOID := range blobOIDs {
		blobPathSets[bOID] = make(map[string]struct{})
		if hint := introducedHints[bOID]; hint != "" {
			if cleanHint, perr := validateFullTreeRelPath(hint, limits); perr == nil {
				blobPathSets[bOID][cleanHint] = struct{}{}
			}
		}
	}

	type commitTouchedFile struct {
		relPath string
		blobOID string
	}
	commitFiles := make(map[string][]commitTouchedFile, len(commits))

	for _, c := range commits {
		rawDiffTree, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "diff-tree", "--no-commit-id", "--raw", "-r", "-m", "--root", "-z", c.OID, "--")
		if err != nil {
			return historyExtractResult{}, domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed running diff-tree for commit", err)
		}
		entries, err := parseCommitRawDiffTree(rawDiffTree, limits)
		if err != nil {
			return historyExtractResult{}, err
		}
		seenInCommit := make(map[string]struct{}, len(entries))
		for _, e := range entries {
			changedPathSet[e.relPath] = struct{}{}
			if e.dstOID != "" && e.dstOID != ZeroOID && (e.dstMode == "100644" || e.dstMode == "100755") {
				key := e.relPath + "\x00" + e.dstOID
				if _, ok := seenInCommit[key]; !ok {
					seenInCommit[key] = struct{}{}
					commitFiles[c.OID] = append(commitFiles[c.OID], commitTouchedFile{
						relPath: e.relPath,
						blobOID: e.dstOID,
					})
				}
				if _, exists := blobPathSets[e.dstOID]; exists {
					blobPathSets[e.dstOID][e.relPath] = struct{}{}
				}
			}
		}
	}

	root, err := os.OpenRoot(workspaceDir)
	if err != nil {
		return historyExtractResult{}, domain.WrapError(domain.ErrInternal, "WORKSPACE_OPEN_FAILED", "failed opening workspace root", err)
	}
	defer root.Close()

	var wsBytes int64

	// Write commit messages and chunked text diffs.
	for _, c := range commits {
		msgPath := path.Join("history", "commits", c.OID, "message.txt")
		if err := writeWorkspaceFileBytes(root, msgPath, []byte(c.Message), limits.MaxWorkspaceBytes, &wsBytes); err != nil {
			return historyExtractResult{}, err
		}
		if err := writeChunkedCommitDiff(ctx, gitBin, homeDir, quarRepo, root, c.OID, limits, &wsBytes); err != nil {
			return historyExtractResult{}, err
		}
	}

	// Write annotated tag messages.
	for _, t := range tags {
		tagPath := path.Join("history", "tags", t.OID+".txt")
		tagContent := fmt.Sprintf("tag %s\nobject %s\ntype %s\n\n%s", t.Name, t.TargetOID, t.TargetType, t.Message)
		if err := writeWorkspaceFileBytes(root, tagPath, []byte(tagContent), limits.MaxWorkspaceBytes, &wsBytes); err != nil {
			return historyExtractResult{}, err
		}
	}

	introducedBlobSet := make(map[string]struct{}, len(blobOIDs))
	for _, bOID := range blobOIDs {
		introducedBlobSet[bOID] = struct{}{}
	}

	type blobRelKey struct {
		blobOID string
		relPath string
	}
	materializedPairs := make(map[blobRelKey]struct{})
	materializedBlobOIDs := make(map[string]struct{})
	var targets []blobWriteTarget
	collisionCounter := 0
	collisionTracker := newPathCollisionTracker()

	scheduleTarget := func(prefixDir, origRelPath, blobOID string, tracker *pathCollisionTracker) error {
		sz := int64(0)
		if m, ok := metaMap[blobOID]; ok {
			sz = m.size
		} else {
			singleMeta, err := batchCheckObjects(ctx, gitBin, homeDir, quarRepo, []string{blobOID})
			if err != nil {
				return err
			}
			m, ok := singleMeta[blobOID]
			if !ok || m.objType != "blob" {
				return domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("missing blob %s during materialization", blobOID))
			}
			if m.size > limits.MaxInflatedObjectBytes {
				return domain.Unprocessable("INFLATED_OBJECT_LIMIT_EXCEEDED", fmt.Sprintf("blob %s exceeds max_inflated_object_bytes", blobOID))
			}
			metaMap[blobOID] = m
			sz = m.size
		}

		if sz < 0 || sz > limits.MaxWorkspaceBytes-wsBytes {
			return domain.Unprocessable("WORKSPACE_LIMIT_EXCEEDED", fmt.Sprintf("workspace size exceeds max_workspace_bytes %d", limits.MaxWorkspaceBytes))
		}

		dstRel := path.Join(prefixDir, origRelPath)
		if err := tracker.add(dstRel, false); err != nil {
			collisionCounter++
			base := safeCollisionBasename(path.Base(origRelPath))
			dstRel = path.Join("history", "collisions", fmt.Sprintf("%s_%04d_%s", blobOID, collisionCounter, base))
		}
		wsBytes += sz
		targets = append(targets, blobWriteTarget{
			blobOID: blobOID,
			relPath: dstRel,
			size:    sz,
		})
		materializedPairs[blobRelKey{blobOID: blobOID, relPath: origRelPath}] = struct{}{}
		materializedBlobOIDs[blobOID] = struct{}{}
		return nil
	}

	// Materialize tip/<ref_key>/<orig_rel_path> for files touched in this push.
	for _, ru := range refs {
		if ru.NewOID == ZeroOID {
			continue
		}
		tipTreeOut, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "rev-parse", "--verify", "--quiet", ru.NewOID+"^{tree}")
		if err != nil {
			continue
		}
		tipTreeOID, perr := domain.ParseGitSHA(strings.TrimSpace(string(tipTreeOut)))
		if perr != nil {
			continue
		}
		rawTipTree, err := runHardenedGit(ctx, gitBin, homeDir, quarRepo, nil, "ls-tree", "-r", "-z", "--", tipTreeOID)
		if err != nil {
			return historyExtractResult{}, domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed reading tip tree", err)
		}
		refPrefix := path.Join("tip", safeRefKey(ru.RefName))
		for _, rec := range bytes.Split(rawTipTree, []byte{0}) {
			if len(rec) == 0 {
				continue
			}
			metaPart, rawPath, ok := strings.Cut(string(rec), "\t")
			if !ok {
				continue
			}
			fields := strings.Fields(metaPart)
			if len(fields) != 3 || fields[1] != "blob" {
				continue
			}
			cleanPath, err := validateFullTreeRelPath(rawPath, limits)
			if err != nil {
				return historyExtractResult{}, err
			}
			blobOID, err := domain.ParseGitSHA(fields[2])
			if err != nil {
				return historyExtractResult{}, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "invalid blob OID in tip tree")
			}
			_, isChanged := changedPathSet[cleanPath]
			_, isNewBlob := introducedBlobSet[blobOID]
			if !isChanged && !isNewBlob {
				continue
			}
			if err := scheduleTarget(refPrefix, cleanPath, blobOID, collisionTracker); err != nil {
				return historyExtractResult{}, err
			}
		}
	}

	// Materialize historical commit blobs not already materialized at the exact (blobOID, relPath).
	for _, c := range commits {
		filesPrefix := path.Join("history", "commits", c.OID, "files")
		for _, cf := range commitFiles[c.OID] {
			if _, ok := materializedPairs[blobRelKey{blobOID: cf.blobOID, relPath: cf.relPath}]; ok {
				continue
			}
			if err := scheduleTarget(filesPrefix, cf.relPath, cf.blobOID, collisionTracker); err != nil {
				return historyExtractResult{}, err
			}
		}
	}

	// Materialize any introduced blobs not yet materialized (e.g. direct tag-to-blob).
	for _, bOID := range blobOIDs {
		if _, ok := materializedBlobOIDs[bOID]; ok {
			continue
		}
		baseName := "blob"
		if ps := blobPathSets[bOID]; len(ps) > 0 {
			var best string
			for p := range ps {
				if best == "" || p < best {
					best = p
				}
			}
			baseName = safeCollisionBasename(path.Base(best))
		}
		fallbackName := fmt.Sprintf("%s_%s", bOID, baseName)
		if err := scheduleTarget("history/blobs", fallbackName, bOID, collisionTracker); err != nil {
			return historyExtractResult{}, err
		}
	}

	if len(targets) > 0 {
		if err := streamBlobsToWorkspace(ctx, gitBin, homeDir, quarRepo, root, targets); err != nil {
			return historyExtractResult{}, err
		}
	}

	changedPaths := make([]string, 0, len(changedPathSet))
	for p := range changedPathSet {
		changedPaths = append(changedPaths, p)
	}
	sort.Strings(changedPaths)

	blobs := make([]ExtractedBlob, 0, len(blobOIDs))
	for _, bOID := range blobOIDs {
		ps := blobPathSets[bOID]
		paths := make([]string, 0, len(ps))
		for p := range ps {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		blobs = append(blobs, ExtractedBlob{
			OID:       bOID,
			SizeBytes: metaMap[bOID].size,
			Paths:     paths,
		})
	}

	if treeOIDs == nil {
		treeOIDs = []string{}
	}
	if commits == nil {
		commits = []ExtractedCommit{}
	}
	if tags == nil {
		tags = []ExtractedTag{}
	}

	return historyExtractResult{
		commits:        commits,
		trees:          treeOIDs,
		blobs:          blobs,
		tags:           tags,
		changedPaths:   changedPaths,
		commitMessages: commitMessages,
	}, nil
}

func extractCommitsAndTags(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	commitOIDs, tagOIDs []string,
) ([]ExtractedCommit, []ExtractedTag, error) {
	if len(commitOIDs) == 0 && len(tagOIDs) == 0 {
		return []ExtractedCommit{}, []ExtractedTag{}, nil
	}

	var stdinBuf bytes.Buffer
	for _, oid := range commitOIDs {
		stdinBuf.WriteString(oid)
		stdinBuf.WriteByte('\n')
	}
	for _, oid := range tagOIDs {
		stdinBuf.WriteString(oid)
		stdinBuf.WriteByte('\n')
	}

	cmd, stdout, stderr, err := startHardenedGitPipe(ctx, gitBin, homeDir, quarRepo, &stdinBuf, "cat-file", "--batch")
	if err != nil {
		return nil, nil, domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed starting cat-file batch", err)
	}

	br := bufio.NewReaderSize(stdout, 64*1024)
	commits := make([]ExtractedCommit, 0, len(commitOIDs))
	tags := make([]ExtractedTag, 0, len(tagOIDs))

	total := len(commitOIDs) + len(tagOIDs)
	for i := 0; i < total; i++ {
		hdrLine, rerr := br.ReadString('\n')
		if rerr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, nil, domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed reading cat-file batch header", rerr)
		}
		hdrLine = strings.TrimRight(hdrLine, "\r\n")
		fields := strings.Fields(hdrLine)
		if len(fields) != 3 {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "unexpected cat-file batch object header")
		}
		oid, objType := fields[0], fields[1]
		sz, perr := strconv.ParseInt(fields[2], 10, 64)
		if perr != nil || sz < 0 {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "invalid object size in cat-file batch")
		}

		payload := make([]byte, sz)
		if _, rerr := io.ReadFull(br, payload); rerr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, nil, domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed reading cat-file batch payload", rerr)
		}
		// Consume trailing LF after object payload.
		if lf, lferr := br.ReadByte(); lferr != nil || lf != '\n' {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "missing newline after cat-file batch object")
		}

		switch objType {
		case "commit":
			c, perr := parseCommitObject(oid, payload)
			if perr != nil {
				_ = stdout.Close()
				_ = cmd.Wait()
				return nil, nil, perr
			}
			commits = append(commits, c)
		case "tag":
			t, perr := parseTagObject(oid, payload)
			if perr != nil {
				_ = stdout.Close()
				_ = cmd.Wait()
				return nil, nil, perr
			}
			tags = append(tags, t)
		}
	}

	_ = stdout.Close()
	if err := cmd.Wait(); err != nil {
		return nil, nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("cat-file batch failed: %s", checkout.SanitizeGitOutput(stderr.String())))
	}
	return commits, tags, nil
}

func parseCommitObject(oid string, raw []byte) (ExtractedCommit, error) {
	headerBytes := raw
	var message string
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		headerBytes = raw[:idx]
		message = string(raw[idx+2:])
	}

	c := ExtractedCommit{
		OID:        oid,
		ParentOIDs: []string{},
		Message:    message,
	}
	for _, line := range strings.Split(string(headerBytes), "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			treeOID, err := domain.ParseGitSHA(strings.TrimPrefix(line, "tree "))
			if err != nil {
				return ExtractedCommit{}, domain.Unprocessable("PACK_FSCK_FAILED", "invalid commit tree OID")
			}
			c.TreeOID = treeOID
		case strings.HasPrefix(line, "parent "):
			parentOID, err := domain.ParseGitSHA(strings.TrimPrefix(line, "parent "))
			if err != nil {
				return ExtractedCommit{}, domain.Unprocessable("PACK_FSCK_FAILED", "invalid commit parent OID")
			}
			c.ParentOIDs = append(c.ParentOIDs, parentOID)
		case strings.HasPrefix(line, "author "):
			c.AuthorName, c.AuthorEmail = parseGitIdentity(strings.TrimPrefix(line, "author "))
		case strings.HasPrefix(line, "committer "):
			c.CommitterName, c.CommitterEmail = parseGitIdentity(strings.TrimPrefix(line, "committer "))
		}
	}
	return c, nil
}

func parseTagObject(oid string, raw []byte) (ExtractedTag, error) {
	headerBytes := raw
	var message string
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		headerBytes = raw[:idx]
		message = string(raw[idx+2:])
	}
	t := ExtractedTag{
		OID:     oid,
		Message: message,
	}
	for _, line := range strings.Split(string(headerBytes), "\n") {
		switch {
		case strings.HasPrefix(line, "object "):
			targetOID, err := domain.ParseGitSHA(strings.TrimPrefix(line, "object "))
			if err != nil {
				return ExtractedTag{}, domain.Unprocessable("PACK_FSCK_FAILED", "invalid tag target OID")
			}
			t.TargetOID = targetOID
		case strings.HasPrefix(line, "type "):
			t.TargetType = strings.TrimSpace(strings.TrimPrefix(line, "type "))
		case strings.HasPrefix(line, "tag "):
			t.Name = strings.TrimPrefix(line, "tag ")
		}
	}
	return t, nil
}

func parseGitIdentity(raw string) (name, email string) {
	lt := strings.IndexByte(raw, '<')
	gt := strings.IndexByte(raw, '>')
	if lt >= 0 && gt > lt {
		name = strings.TrimSpace(raw[:lt])
		email = strings.TrimSpace(raw[lt+1 : gt])
	}
	return name, email
}

type diffTreeEntry struct {
	dstMode string
	dstOID  string
	relPath string
}

func parseCommitRawDiffTree(raw []byte, limits Limits) ([]diffTreeEntry, error) {
	tokens := bytes.Split(raw, []byte{0})
	out := make([]diffTreeEntry, 0)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if len(tok) == 0 || tok[0] != ':' {
			continue
		}
		fields := strings.Fields(string(tok[1:]))
		if len(fields) < 5 {
			return nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "malformed diff-tree raw header")
		}
		dstMode, dstOID, status := fields[1], fields[3], fields[4]
		if i+1 >= len(tokens) {
			return nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "missing path in diff-tree output")
		}
		i++
		p1, err := validateFullTreeRelPath(string(tokens[i]), limits)
		if err != nil {
			return nil, err
		}
		rel := p1
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i+1 >= len(tokens) {
				return nil, domain.Unprocessable("HISTORY_EXTRACT_FAILED", "missing destination path in diff-tree output")
			}
			i++
			p2, err := validateFullTreeRelPath(string(tokens[i]), limits)
			if err != nil {
				return nil, err
			}
			rel = p2
		}
		out = append(out, diffTreeEntry{
			dstMode: dstMode,
			dstOID:  strings.ToLower(dstOID),
			relPath: rel,
		})
	}
	return out, nil
}

func writeChunkedCommitDiff(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	root *os.Root,
	commitOID string,
	limits Limits,
	wsBytes *int64,
) error {
	cmd, stdout, stderr, err := startHardenedGitPipe(ctx, gitBin, homeDir, quarRepo, nil, "diff-tree", "--no-commit-id", "-p", "-m", "--root", "--no-ext-diff", "--no-color", commitOID, "--")
	if err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed running diff-tree patch", err)
	}

	maxChunk := limits.MaxDiffBytesPerCommit
	var chunkBuf bytes.Buffer
	chunkIdx := 0

	flushChunk := func(isSingle bool) error {
		if chunkBuf.Len() == 0 {
			return nil
		}
		chunkIdx++
		name := "diff.patch"
		if !isSingle || chunkIdx > 1 {
			name = fmt.Sprintf("diff_%03d.patch", chunkIdx)
		}
		relPath := path.Join("history", "commits", commitOID, name)
		err := writeWorkspaceFileBytes(root, relPath, chunkBuf.Bytes(), limits.MaxWorkspaceBytes, wsBytes)
		chunkBuf.Reset()
		return err
	}

	br := bufio.NewReaderSize(stdout, 32*1024)
	for {
		frag, readErr := br.ReadBytes('\n')
		if len(frag) > 0 {
			for len(frag) > 0 {
				if int64(len(frag)) > maxChunk {
					if chunkBuf.Len() > 0 {
						if err := flushChunk(false); err != nil {
							_ = stdout.Close()
							_ = cmd.Wait()
							return err
						}
					}
					part := frag[:maxChunk]
					frag = frag[maxChunk:]
					chunkBuf.Write(part)
					if err := flushChunk(false); err != nil {
						_ = stdout.Close()
						_ = cmd.Wait()
						return err
					}
					continue
				}
				if chunkBuf.Len() > 0 && int64(len(frag)) > maxChunk-int64(chunkBuf.Len()) {
					if err := flushChunk(false); err != nil {
						_ = stdout.Close()
						_ = cmd.Wait()
						return err
					}
				}
				chunkBuf.Write(frag)
				frag = nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed reading diff-tree patch", readErr)
		}
	}

	_ = stdout.Close()
	if err := cmd.Wait(); err != nil {
		return domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("diff-tree patch failed: %s", checkout.SanitizeGitOutput(stderr.String())))
	}

	if chunkBuf.Len() > 0 {
		if err := flushChunk(chunkIdx == 0); err != nil {
			return err
		}
	}
	return nil
}

func streamBlobsToWorkspace(
	ctx context.Context,
	gitBin, homeDir, quarRepo string,
	root *os.Root,
	targets []blobWriteTarget,
) error {
	var stdinBuf bytes.Buffer
	for _, t := range targets {
		stdinBuf.WriteString(t.blobOID)
		stdinBuf.WriteByte('\n')
	}

	cmd, stdout, stderr, err := startHardenedGitPipe(ctx, gitBin, homeDir, quarRepo, &stdinBuf, "cat-file", "--batch")
	if err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed starting blob cat-file batch", err)
	}

	br := bufio.NewReaderSize(stdout, 64*1024)
	for _, t := range targets {
		hdrLine, rerr := br.ReadString('\n')
		if rerr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.WrapError(domain.ErrUnprocessable, "HISTORY_EXTRACT_FAILED", "failed reading blob header from cat-file batch", rerr)
		}
		hdrLine = strings.TrimRight(hdrLine, "\r\n")
		fields := strings.Fields(hdrLine)
		if len(fields) != 3 || fields[1] != "blob" {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("unexpected blob header for %s", t.blobOID))
		}
		sz, perr := strconv.ParseInt(fields[2], 10, 64)
		if perr != nil || sz < 0 || sz != t.size {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("blob size mismatch for %s", t.blobOID))
		}

		if err := mkdirAllInRoot(root, path.Dir(t.relPath)); err != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return err
		}

		f, oerr := root.OpenFile(t.relPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
		if oerr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.WrapError(domain.ErrInternal, "WORKSPACE_WRITE_FAILED", "failed creating materialized workspace blob file", oerr)
		}
		_, copyErr := io.CopyN(f, br, sz)
		chmodErr := f.Chmod(0o644)
		closeErr := f.Close()
		if copyErr != nil || chmodErr != nil || closeErr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.WrapError(domain.ErrInternal, "WORKSPACE_WRITE_FAILED", "failed writing materialized workspace blob file", firstErr(copyErr, chmodErr, closeErr))
		}

		if lf, lferr := br.ReadByte(); lferr != nil || lf != '\n' {
			_ = stdout.Close()
			_ = cmd.Wait()
			return domain.Unprocessable("HISTORY_EXTRACT_FAILED", "missing trailing newline after blob payload")
		}
	}

	_ = stdout.Close()
	if err := cmd.Wait(); err != nil {
		return domain.Unprocessable("HISTORY_EXTRACT_FAILED", fmt.Sprintf("blob cat-file batch failed: %s", checkout.SanitizeGitOutput(stderr.String())))
	}
	return nil
}

func writeWorkspaceFileBytes(root *os.Root, relPath string, data []byte, maxWorkspaceBytes int64, wsBytes *int64) error {
	sz := int64(len(data))
	if sz > maxWorkspaceBytes-*wsBytes {
		return domain.Unprocessable("WORKSPACE_LIMIT_EXCEEDED", fmt.Sprintf("workspace size exceeds max_workspace_bytes %d", maxWorkspaceBytes))
	}
	if err := mkdirAllInRoot(root, path.Dir(relPath)); err != nil {
		return err
	}
	f, err := root.OpenFile(relPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "WORKSPACE_WRITE_FAILED", "failed creating workspace metadata file", err)
	}
	_, writeErr := f.Write(data)
	chmodErr := f.Chmod(0o644)
	closeErr := f.Close()
	if err := firstErr(writeErr, chmodErr, closeErr); err != nil {
		return domain.WrapError(domain.ErrInternal, "WORKSPACE_WRITE_FAILED", "failed writing workspace metadata file", err)
	}
	*wsBytes += sz
	return nil
}

func mkdirAllInRoot(root *os.Root, relDir string) error {
	if relDir == "" || relDir == "." {
		return nil
	}
	parts := strings.Split(relDir, "/")
	curr := ""
	for _, p := range parts {
		if curr == "" {
			curr = p
		} else {
			curr = curr + "/" + p
		}
		if err := root.Mkdir(curr, 0o755); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return domain.WrapError(domain.ErrInternal, "WORKSPACE_MKDIR_FAILED", "failed creating workspace directory", err)
			}
		} else {
			_ = root.Chmod(curr, 0o755)
		}
	}
	return nil
}

func safeRefKey(refName string) string {
	digest := domain.SHA256Hex([]byte(refName))[:8]
	var b strings.Builder
	for _, r := range refName {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 48 {
			break
		}
	}
	san := strings.Trim(b.String(), "_.")
	if san == "" {
		san = "ref"
	}
	return san + "_" + digest
}

func safeCollisionBasename(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "file"
	}
	return out
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
