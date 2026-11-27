package quarantine

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/observability"
)

type panicOnReadReader struct {
	t *testing.T
}

func (p *panicOnReadReader) Read([]byte) (int, error) {
	p.t.Fatalf("PackReader was read during pre-pack validation failure")
	return 0, io.EOF
}

type infiniteZeroReader struct {
	read int64
}

func (z *infiniteZeroReader) Read(p []byte) (int, error) {
	clear(p)
	z.read += int64(len(p))
	return len(p), nil
}

func TestPrePackValidationRejectsWithoutReadingPack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	metrics, err := observability.NewMetrics(observability.MetricsConfig{})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "quarantine-test",
	})

	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{
		Metrics: metrics,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	validOID := strings.Repeat("a", 40)
	cases := []struct {
		name     string
		refs     []RefUpdate
		resolver ExistingRefResolver
		limits   Limits
		wantCode string
	}{
		{
			name:     "empty_ref_updates",
			refs:     nil,
			wantCode: "EMPTY_REF_UPDATES",
		},
		{
			name: "max_ref_updates_exceeded",
			refs: []RefUpdate{
				{RefName: "refs/heads/a", OldOID: ZeroOID, NewOID: validOID},
				{RefName: "refs/heads/b", OldOID: ZeroOID, NewOID: validOID},
			},
			limits:   Limits{MaxRefUpdates: 1},
			wantCode: "REF_UPDATES_LIMIT_EXCEEDED",
		},
		{
			name: "duplicate_ref_update",
			refs: []RefUpdate{
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: validOID},
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DUPLICATE_REF_UPDATE",
		},
		{
			name: "invalid_git_sha",
			refs: []RefUpdate{
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: "not-a-sha"},
			},
			wantCode: "INVALID_GIT_SHA",
		},
		{
			name: "zero_to_zero_ref_update",
			refs: []RefUpdate{
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: ZeroOID},
			},
			wantCode: "INVALID_REF_UPDATE",
		},
		{
			name: "disallowed_refs_replace",
			refs: []RefUpdate{
				{RefName: "refs/replace/" + validOID, OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DISALLOWED_REF_NAMESPACE",
		},
		{
			name: "disallowed_refs_notes",
			refs: []RefUpdate{
				{RefName: "refs/notes/commits", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DISALLOWED_REF_NAMESPACE",
		},
		{
			name: "disallowed_refs_pull",
			refs: []RefUpdate{
				{RefName: "refs/pull/42/head", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DISALLOWED_REF_NAMESPACE",
		},
		{
			name: "disallowed_refs_original",
			refs: []RefUpdate{
				{RefName: "refs/original/heads/main", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DISALLOWED_REF_NAMESPACE",
		},
		{
			name: "disallowed_HEAD",
			refs: []RefUpdate{
				{RefName: "HEAD", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "DISALLOWED_REF_NAMESPACE",
		},
		{
			name: "invalid_ref_syntax_leading_dash",
			refs: []RefUpdate{
				{RefName: "-evil", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "INVALID_REF_NAME",
		},
		{
			name: "invalid_ref_syntax_leading_dash_segment",
			refs: []RefUpdate{
				{RefName: "refs/heads/-evil", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "INVALID_REF_NAME",
		},
		{
			name: "invalid_ref_syntax_hidden_segment",
			refs: []RefUpdate{
				{RefName: "refs/heads/.hidden", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "INVALID_REF_NAME",
		},
		{
			name: "invalid_ref_syntax_dotdot",
			refs: []RefUpdate{
				{RefName: "refs/heads/a..b", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "INVALID_REF_NAME",
		},
		{
			name: "invalid_ref_syntax_dotlock",
			refs: []RefUpdate{
				{RefName: "refs/heads/main.lock", OldOID: ZeroOID, NewOID: validOID},
			},
			wantCode: "INVALID_REF_NAME",
		},
		{
			name: "cas_mismatch",
			refs: []RefUpdate{
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: validOID},
			},
			resolver: &testRefResolver{refs: map[string]string{"refs/heads/main": strings.Repeat("b", 40)}},
			wantCode: "REF_CAS_MISMATCH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unpacker.Unpack(ctx, UnpackRequest{
				PushSessionID:       uuid.New(),
				PackReader:          &panicOnReadReader{t: t},
				RefUpdates:          tc.refs,
				ExistingRefResolver: tc.resolver,
				Limits:              tc.limits,
			})
			assertDomainErrCode(t, err, tc.wantCode)
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `custodian_push_quarantine_rejections_total{reason="disallowed_ref_namespace"}`) {
		t.Fatalf("expected quarantine rejection metric in /metrics output, status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("log line invalid JSON: %v (%s)", err, line)
		}
		if _, hasSession := obj["push_session_id"]; !hasSession {
			t.Fatalf("expected allowlisted push_session_id in log line: %s", line)
		}
	}
}

func TestStreamingPackBoundsAndMalformedPacks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	repo := initTestRepo(t, false)
	c1 := commitFile(t, repo, "main.go", "package main\nfunc main() {}\n", "init")
	validPack := buildPackFromRevs(t, repo, []string{c1}, false)

	t.Run("max_pack_bytes_streaming_abort", func(t *testing.T) {
		zr := &infiniteZeroReader{}
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    zr,
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
			Limits:        Limits{MaxPackBytes: 4096},
		})
		assertDomainErrCode(t, err, "PACK_SIZE_LIMIT_EXCEEDED")
		// Must abort shortly after MaxPackBytes + buffer without buffering gigabytes.
		if zr.read > 128*1024 {
			t.Fatalf("reader read %d bytes despite MaxPackBytes=4096", zr.read)
		}
	})

	t.Run("max_objects_header_exceeded", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("PACK")
		_ = binary.Write(&buf, binary.BigEndian, uint32(2))
		_ = binary.Write(&buf, binary.BigEndian, uint32(999999))
		sum := sha1.Sum(buf.Bytes())
		buf.Write(sum[:])

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(buf.Bytes()),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
			Limits:        Limits{MaxObjects: 5},
		})
		assertDomainErrCode(t, err, "OBJECT_COUNT_LIMIT_EXCEEDED")
	})

	t.Run("unsupported_pack_version", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("PACK")
		_ = binary.Write(&buf, binary.BigEndian, uint32(3))
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))
		sum := sha1.Sum(buf.Bytes())
		buf.Write(sum[:])

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(buf.Bytes()),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
		})
		assertDomainErrCode(t, err, "UNSUPPORTED_PACK_VERSION")
	})

	t.Run("truncated_pack_under_32_bytes", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(validPack[:20]),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
		})
		assertDomainErrCode(t, err, "MALFORMED_PACK")
	})

	t.Run("bad_checksum_trailer", func(t *testing.T) {
		corrupt := append([]byte(nil), validPack...)
		corrupt[len(corrupt)-1] ^= 0xff
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(corrupt),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
		})
		assertDomainErrCode(t, err, "INVALID_PACK_CHECKSUM")
	})

	t.Run("trailing_garbage_after_pack_objects", func(t *testing.T) {
		// Insert extra byte before the 20-byte trailer and recompute SHA-1.
		bodyWithGarbage := append([]byte(nil), validPack[:len(validPack)-20]...)
		bodyWithGarbage = append(bodyWithGarbage, 0xaa, 0xbb)
		sum := sha1.Sum(bodyWithGarbage)
		pack := append(bodyWithGarbage, sum[:]...)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
		})
		assertDomainErrCode(t, err, "MALFORMED_PACK")
	})
}

func TestZipAndDeltaBombRejections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}
	dummyTarget := strings.Repeat("c", 40)

	t.Run("lying_zlib_blob_bomb", func(t *testing.T) {
		// Declare size=100 in pack header, but compress 65536 zero bytes!
		bombPayload := bytes.Repeat([]byte("A"), 65536)
		pack := buildRawPack([]rawPackEntry{
			{
				objType:              packObjBlob,
				rawPayload:           bombPayload,
				declaredSizeOverride: 100,
			},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
			Limits:        Limits{MaxInflatedObjectBytes: 32768},
		})
		assertDomainErrCode(t, err, "INFLATED_OBJECT_LIMIT_EXCEEDED")
	})

	t.Run("declared_object_exceeds_max_inflated", func(t *testing.T) {
		pack := buildRawPack([]rawPackEntry{
			{
				objType:              packObjBlob,
				rawPayload:           bytes.Repeat([]byte("B"), 40000),
				declaredSizeOverride: -1,
			},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
			Limits:        Limits{MaxInflatedObjectBytes: 32768},
		})
		assertDomainErrCode(t, err, "INFLATED_OBJECT_LIMIT_EXCEEDED")
	})

	t.Run("aggregate_total_inflated_limit", func(t *testing.T) {
		chunk := bytes.Repeat([]byte("Z"), 20000)
		pack := buildRawPack([]rawPackEntry{
			{objType: packObjBlob, rawPayload: chunk, declaredSizeOverride: -1},
			{objType: packObjBlob, rawPayload: chunk, declaredSizeOverride: -1},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
			Limits:        Limits{MaxInflatedObjectBytes: 32768, MaxTotalInflatedBytes: 30000},
		})
		assertDomainErrCode(t, err, "TOTAL_INFLATED_LIMIT_EXCEEDED")
	})

	t.Run("ref_delta_bomb_exceeding_target_size", func(t *testing.T) {
		baseBlob := bytes.Repeat([]byte("X"), 4096)
		baseOID := hashGitObjectRaw("blob", baseBlob)
		var delta bytes.Buffer
		delta.Write(encodeLEB128(4096))  // baseSize
		delta.Write(encodeLEB128(65536)) // targetSize (> 32768)
		delta.WriteByte(0x80 | 0x04)     // dummy copy op

		pack := buildRawPack([]rawPackEntry{
			{objType: packObjBlob, rawPayload: baseBlob, declaredSizeOverride: -1},
			{objType: packObjRefDelta, rawPayload: delta.Bytes(), declaredSizeOverride: -1, refDeltaBase: baseOID},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
			Limits:        Limits{MaxInflatedObjectBytes: 32768},
		})
		assertDomainErrCode(t, err, "INFLATED_OBJECT_LIMIT_EXCEEDED")
	})

	t.Run("ofs_delta_bomb_and_depth_limit", func(t *testing.T) {
		baseBlob := []byte("hello world")
		var delta1 bytes.Buffer
		delta1.Write(encodeLEB128(uint64(len(baseBlob))))
		delta1.Write(encodeLEB128(uint64(len(baseBlob))))
		delta1.WriteByte(0x90) // copy 0..len

		// Measure offset of entry 0 (offset 12) vs entry 1.
		hdr0 := encodePackEntryHeader(packObjBlob, uint64(len(baseBlob)))
		z0 := compressZlib(baseBlob)
		entry1Offset := uint64(12 + len(hdr0) + len(z0))
		neg1 := entry1Offset - 12

		hdr1 := encodePackEntryHeader(packObjOfsDelta, uint64(delta1.Len()))
		ofs1 := encodeOfsDeltaOffset(neg1)
		z1 := compressZlib(delta1.Bytes())
		entry2Offset := entry1Offset + uint64(len(hdr1)+len(ofs1)+len(z1))
		neg2 := entry2Offset - entry1Offset

		pack := buildRawPack([]rawPackEntry{
			{objType: packObjBlob, rawPayload: baseBlob, declaredSizeOverride: -1},
			{objType: packObjOfsDelta, rawPayload: delta1.Bytes(), declaredSizeOverride: -1, ofsDeltaNeg: neg1},
			{objType: packObjOfsDelta, rawPayload: delta1.Bytes(), declaredSizeOverride: -1, ofsDeltaNeg: neg2},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
			Limits:        Limits{MaxDeltaDepth: 1},
		})
		assertDomainErrCode(t, err, "DELTA_DEPTH_LIMIT_EXCEEDED")
	})

	t.Run("ofs_delta_invalid_offset_rejected", func(t *testing.T) {
		pack := buildRawPack([]rawPackEntry{
			{objType: packObjOfsDelta, rawPayload: []byte{1, 1, 0}, declaredSizeOverride: -1, ofsDeltaNeg: 999},
		})
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: dummyTarget}},
		})
		assertDomainErrCode(t, err, "MALFORMED_PACK")
	})
}

func TestUnreferencedObjectsAndBaselineAlternates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	// Build a baseline bare repo with 1 commit AND an extra dangling orphan blob in baseline.
	work := initTestRepo(t, false)
	c1 := commitFile(t, work, "base.txt", strings.Repeat("baseline content line\n", 20), "base")

	bare := initTestRepo(t, true)
	runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")
	_ = writeGitObjectToRepo(t, bare, "blob", []byte("pre-existing dangling blob in baseline"))

	// Make c2 modifying base.txt slightly (so thin pack generates OBJ_REF_DELTA against c1's blob).
	c2 := commitFile(t, work, "base.txt", strings.Repeat("baseline content line\n", 20)+"added line\n", "c2")
	thinPack := buildPackFromRevs(t, work, []string{c2, "^" + c1}, true)

	t.Run("thin_pack_without_baseline_fails_closed", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(thinPack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c2}},
		})
		assertDomainErrCode(t, err, "UNRESOLVED_THIN_DELTA")
	})

	t.Run("non_zero_old_oid_without_baseline_fails_closed", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(thinPack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2}},
		})
		assertDomainErrCode(t, err, "BASELINE_OBJECT_MISSING")
	})

	t.Run("thin_pack_with_baseline_and_dangling_baseline_blob_succeeds", func(t *testing.T) {
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(thinPack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2}},
			BaselineRepoDir: bare,
		})
		if err != nil {
			t.Fatalf("Unpack with baseline failed: %v", err)
		}
		defer res.Close()
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		if len(res.Commits) != 1 || res.Commits[0].OID != c2 {
			t.Fatalf("unexpected commits: %+v", res.Commits)
		}
	})

	t.Run("standalone_pack_with_orphan_blob_rejected", func(t *testing.T) {
		orphanOID := writeGitObjectToRepo(t, work, "blob", []byte("unreferenced orphan payload"))
		packWithOrphan := buildPackFromRevs(t, work, []string{c2, orphanOID, "^" + c1}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(packWithOrphan),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2}},
			BaselineRepoDir: bare,
		})
		assertDomainErrCode(t, err, "UNREFERENCED_OBJECT")
	})

	t.Run("pure_deletion_with_packed_objects_rejected", func(t *testing.T) {
		orphanOID := writeGitObjectToRepo(t, work, "blob", []byte("deletion smuggling blob"))
		orphanPack := buildPackFromRevs(t, work, []string{orphanOID}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(orphanPack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: ZeroOID}},
			BaselineRepoDir: bare,
		})
		assertDomainErrCode(t, err, "UNREFERENCED_OBJECT")
	})
}

func TestTreePathSymlinkSubmoduleAndCollisionHardening(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	t.Run("non_tip_historical_symlink_rejected", func(t *testing.T) {
		repo := initTestRepo(t, false)
		_ = commitFile(t, repo, "a.txt", "clean\n", "c1")
		if err := os.Symlink("/etc/passwd", filepath.Join(repo, "evil_link")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		runTestGit(t, repo, nil, nil, "add", "evil_link")
		runTestGit(t, repo, nil, nil, "commit", "-m", "add symlink")
		runTestGit(t, repo, nil, nil, "rm", "evil_link")
		runTestGit(t, repo, nil, nil, "commit", "-m", "remove symlink before tip")
		tip := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "HEAD"))

		pack := buildPackFromRevs(t, repo, []string{tip}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: tip}},
		})
		assertDomainErrCode(t, err, "UNSAFE_SYMLINK")
	})

	t.Run("non_tip_historical_submodule_and_gitmodules_rejected", func(t *testing.T) {
		repo := initTestRepo(t, false)
		_ = commitFile(t, repo, "a.txt", "clean\n", "c1")
		_ = commitFile(t, repo, ".gitmodules", "[submodule \"x\"]\n\tpath = x\n\turl = https://evil.example/x.git\n", "add gitmodules")
		runTestGit(t, repo, nil, nil, "rm", ".gitmodules")
		tip := commitFile(t, repo, "b.txt", "clean2\n", "remove gitmodules")
		pack := buildPackFromRevs(t, repo, []string{tip}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: tip}},
		})
		assertDomainErrCode(t, err, "SUBMODULE_NOT_ALLOWED")

		// Also test raw 160000 gitlink entry in a non-tip tree.
		repo2 := initTestRepo(t, false)
		blobOID := writeGitObjectToRepo(t, repo2, "blob", []byte("hello"))
		subCommit := commitFile(t, repo2, "readme.txt", "sub", "sub")
		gitlinkTree := writeGitObjectToRepo(t, repo2, "tree", buildRawTreePayload([]struct {
			mode string
			name string
			oid  [20]byte
		}{
			{mode: "160000", name: "submod", oid: mustHex20(t, subCommit)},
		}))
		cBad := strings.TrimSpace(runTestGit(t, repo2, nil, []byte("bad"), "commit-tree", gitlinkTree, "-p", subCommit))
		cleanTree := writeGitObjectToRepo(t, repo2, "tree", buildRawTreePayload([]struct {
			mode string
			name string
			oid  [20]byte
		}{
			{mode: "100644", name: "clean.txt", oid: mustHex20(t, blobOID)},
		}))
		cTip := strings.TrimSpace(runTestGit(t, repo2, nil, []byte("clean tip"), "commit-tree", cleanTree, "-p", cBad))
		pack2 := buildPackFromRevs(t, repo2, []string{cTip}, false)
		_, err = unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack2),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: cTip}},
		})
		assertDomainErrCode(t, err, "SUBMODULE_NOT_ALLOWED")
	})

	t.Run("raw_tree_traversal_and_dotgit_rejected", func(t *testing.T) {
		for _, unsafeName := range []string{"../escape.txt", ".git", ".GIT\u200b"} {
			repo := initTestRepo(t, false)
			blobOID := writeGitObjectToRepo(t, repo, "blob", []byte("pwn"))
			treePayload := buildRawTreePayload([]struct {
				mode string
				name string
				oid  [20]byte
			}{
				{mode: "100644", name: unsafeName, oid: mustHex20(t, blobOID)},
			})
			treeOID := hashGitObjectRaw("tree", treePayload)
			commitPayload := []byte(
				"tree " + fmtHex20(treeOID) + "\n" +
					"author Test <t@e.com> 1700000000 +0000\n" +
					"committer Test <t@e.com> 1700000000 +0000\n\n" +
					"evil tree\n",
			)
			commitOID := hashGitObjectRaw("commit", commitPayload)
			pack := buildRawPack([]rawPackEntry{
				{objType: packObjCommit, rawPayload: commitPayload, declaredSizeOverride: -1},
				{objType: packObjTree, rawPayload: treePayload, declaredSizeOverride: -1},
				{objType: packObjBlob, rawPayload: []byte("pwn"), declaredSizeOverride: -1},
			})
			_, err := unpacker.Unpack(ctx, UnpackRequest{
				PushSessionID: uuid.New(),
				PackReader:    bytes.NewReader(pack),
				RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: fmtHex20(commitOID)}},
			})
			if err == nil {
				t.Fatalf("expected unsafe name %q to be rejected", unsafeName)
			}
		}
	})

	t.Run("case_and_unicode_nfc_nfd_collisions_rejected", func(t *testing.T) {
		for _, pair := range [][2]string{
			{"README.md", "readme.md"},
			{"cafe\u0301.txt", "caf\u00e9.txt"},
		} {
			repo := initTestRepo(t, false)
			b1 := writeGitObjectToRepo(t, repo, "blob", []byte("one"))
			b2 := writeGitObjectToRepo(t, repo, "blob", []byte("two"))
			treePayload := buildRawTreePayload([]struct {
				mode string
				name string
				oid  [20]byte
			}{
				{mode: "100644", name: pair[0], oid: mustHex20(t, b1)},
				{mode: "100644", name: pair[1], oid: mustHex20(t, b2)},
			})
			treeOID := hashGitObjectRaw("tree", treePayload)
			commitPayload := []byte(
				"tree " + fmtHex20(treeOID) + "\n" +
					"author Test <t@e.com> 1700000000 +0000\n" +
					"committer Test <t@e.com> 1700000000 +0000\n\n" +
					"collision\n",
			)
			commitOID := hashGitObjectRaw("commit", commitPayload)
			pack := buildRawPack([]rawPackEntry{
				{objType: packObjCommit, rawPayload: commitPayload, declaredSizeOverride: -1},
				{objType: packObjTree, rawPayload: treePayload, declaredSizeOverride: -1},
				{objType: packObjBlob, rawPayload: []byte("one"), declaredSizeOverride: -1},
				{objType: packObjBlob, rawPayload: []byte("two"), declaredSizeOverride: -1},
			})
			_, err := unpacker.Unpack(ctx, UnpackRequest{
				PushSessionID: uuid.New(),
				PackReader:    bytes.NewReader(pack),
				RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: fmtHex20(commitOID)}},
			})
			assertDomainErrCode(t, err, "PATH_COLLISION")
		}
	})

	t.Run("max_path_depth_and_bytes_rejected", func(t *testing.T) {
		repo := initTestRepo(t, false)
		tip := commitFile(t, repo, "a/b/c/d/file.txt", "deep", "deep")
		pack := buildPackFromRevs(t, repo, []string{tip}, false)

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: tip}},
			Limits:        Limits{MaxPathDepth: 3},
		})
		assertDomainErrCode(t, err, "UNSAFE_TREE_PATH")

		_, err = unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: tip}},
			Limits:        Limits{MaxPathBytes: 8},
		})
		assertDomainErrCode(t, err, "UNSAFE_TREE_PATH")
	})
}

func TestRefTargetTypesAndTagDepth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	repo := initTestRepo(t, false)
	c1 := commitFile(t, repo, "a.txt", "hello", "c1")
	blobOID := writeGitObjectToRepo(t, repo, "blob", []byte("direct blob"))

	t.Run("branch_pointing_to_blob_rejected", func(t *testing.T) {
		pack := buildPackFromRevs(t, repo, []string{blobOID}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: blobOID}},
		})
		assertDomainErrCode(t, err, "INVALID_REF_TARGET_TYPE")
	})

	t.Run("tag_to_blob_rejected_by_default_and_allowed_when_configured", func(t *testing.T) {
		pack := buildPackFromRevs(t, repo, []string{blobOID}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/tags/blobtag", OldOID: ZeroOID, NewOID: blobOID}},
		})
		assertDomainErrCode(t, err, "INVALID_REF_TARGET_TYPE")

		uAllow, _ := NewQuarantineUnpacker(UnpackerConfig{AllowTagToNonCommit: true})
		res, err := uAllow.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/tags/blobtag", OldOID: ZeroOID, NewOID: blobOID}},
		})
		if err != nil {
			t.Fatalf("expected AllowTagToNonCommit to succeed: %v", err)
		}
		defer res.Close()
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		matches, _ := filepath.Glob(filepath.Join(res.WorkspaceDir, "history", "blobs", blobOID+"_*"))
		if len(matches) != 1 {
			t.Fatalf("expected direct blob materialized in history/blobs/, got %v", matches)
		}
	})

	t.Run("nested_tag_depth_exceeded_rejected", func(t *testing.T) {
		// Create tag1 -> c1, tag2 -> tag1, tag3 -> tag2
		runTestGit(t, repo, nil, nil, "tag", "-a", "t1", "-m", "m1", c1)
		t1 := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "t1"))
		runTestGit(t, repo, nil, nil, "tag", "-a", "t2", "-m", "m2", t1)
		t2 := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "t2"))
		runTestGit(t, repo, nil, nil, "tag", "-a", "t3", "-m", "m3", t2)
		t3 := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "t3"))

		pack := buildPackFromRevs(t, repo, []string{t3}, false)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/tags/t3", OldOID: ZeroOID, NewOID: t3}},
			Limits:        Limits{MaxTagDepth: 2},
		})
		assertDomainErrCode(t, err, "TAG_DEPTH_LIMIT_EXCEEDED")
	})
}

func TestPoisonedHostGitConfigAndSmudgeFiltersIgnored(t *testing.T) {
	ctx := context.Background()
	poisonDir := t.TempDir()
	markerFile := filepath.Join(poisonDir, "pwned_marker")

	evilHome := filepath.Join(poisonDir, "home")
	evilXDG := filepath.Join(poisonDir, "xdg")
	_ = os.MkdirAll(filepath.Join(evilXDG, "git"), 0o755)
	_ = os.MkdirAll(evilHome, 0o755)

	evilConfig := "[core]\n\thooksPath = " + poisonDir + "\n\tfsmonitor = touch " + markerFile + "\n" +
		"[filter \"evil\"]\n\tsmudge = sh -c 'touch " + markerFile + " && echo SMUDGED'\n\tclean = cat\n"
	_ = os.WriteFile(filepath.Join(evilHome, ".gitconfig"), []byte(evilConfig), 0o644)
	_ = os.WriteFile(filepath.Join(evilXDG, "git", "config"), []byte(evilConfig), 0o644)

	t.Setenv("HOME", evilHome)
	t.Setenv("XDG_CONFIG_HOME", evilXDG)
	t.Setenv("GIT_CONFIG_PARAMETERS", "'filter.evil.smudge=touch "+markerFile+"'")

	// Build pack in a clean temp repo using clean env so local pack creation isn't affected by t.Setenv.
	repo := initTestRepo(t, false)
	cleanEnv := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Test User",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=2025-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=Test User",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_COMMITTER_DATE=2025-01-01T00:00:00Z",
	}
	_ = os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("*.txt filter=evil\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "raw.txt"), []byte("UNSMUDGED_ORIGINAL_BYTES"), 0o644)
	runTestGit(t, repo, cleanEnv, nil, "add", ".gitattributes", "raw.txt")
	runTestGit(t, repo, cleanEnv, nil, "commit", "-m", "smudge trap")
	tip := strings.TrimSpace(runTestGit(t, repo, cleanEnv, nil, "rev-parse", "HEAD"))
	pack := buildPackFromRevs(t, repo, []string{tip}, false)

	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}
	res, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(pack),
		RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: tip}},
	})
	if err != nil {
		t.Fatalf("Unpack failed under poisoned env: %v", err)
	}
	defer res.Close()

	if _, err := os.Stat(markerFile); !os.IsNotExist(err) {
		t.Fatalf("poisoned git hook/filter executed and created marker file %s", markerFile)
	}

	rawMatches, err := filepath.Glob(filepath.Join(res.WorkspaceDir, "tip", "*", "raw.txt"))
	if err != nil || len(rawMatches) != 1 {
		t.Fatalf("expected 1 materialized raw.txt, got %v (err=%v)", rawMatches, err)
	}
	gotBytes, err := os.ReadFile(rawMatches[0])
	if err != nil {
		t.Fatalf("read raw.txt: %v", err)
	}
	if string(gotBytes) != "UNSMUDGED_ORIGINAL_BYTES" {
		t.Fatalf("raw.txt content = %q, want UNSMUDGED_ORIGINAL_BYTES", string(gotBytes))
	}
}

func TestLimitsAndBaselineEdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Negative default limits fail closed in constructor.
	if _, err := NewQuarantineUnpacker(UnpackerConfig{DefaultLimits: Limits{MaxPackBytes: -1}}); err == nil {
		t.Fatalf("expected error for negative DefaultLimits.MaxPackBytes")
	}

	// Scaling MaxInflatedObjectBytes > 32 MiB auto-scales MaxTotalInflatedBytes >= 16x.
	resolved, err := (Limits{MaxInflatedObjectBytes: 64 << 20}).resolve(defaultLimits())
	if err != nil {
		t.Fatalf("Limits.resolve: %v", err)
	}
	if resolved.MaxTotalInflatedBytes < (64<<20)*16 {
		t.Fatalf("MaxTotalInflatedBytes = %d, want >= %d", resolved.MaxTotalInflatedBytes, int64(64<<20)*16)
	}

	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	t.Run("negative_request_limits_rejected", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(nil),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: strings.Repeat("a", 40)}},
			Limits:        Limits{MaxObjects: -5},
		})
		assertDomainErrCode(t, err, "INVALID_LIMITS")
	})

	t.Run("symlink_and_missing_baseline_dir_rejected", func(t *testing.T) {
		realDir := t.TempDir()
		linkDir := filepath.Join(t.TempDir(), "baseline-link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(nil),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: strings.Repeat("a", 40), NewOID: ZeroOID}},
			BaselineRepoDir: linkDir,
		})
		assertDomainErrCode(t, err, "UNSAFE_BASELINE_DIR")

		_, err = unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(nil),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: strings.Repeat("a", 40), NewOID: ZeroOID}},
			BaselineRepoDir: filepath.Join(t.TempDir(), "does-not-exist"),
		})
		assertDomainErrCode(t, err, "INVALID_BASELINE_DIR")
	})

	t.Run("empty_pack_branch_create_on_existing_baseline_commit_vs_missing_target", func(t *testing.T) {
		work := initTestRepo(t, false)
		c1 := commitFile(t, work, "a.txt", "hello\n", "init")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(nil),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/copy", OldOID: ZeroOID, NewOID: c1}},
			BaselineRepoDir: bare,
		})
		if err != nil {
			t.Fatalf("expected empty-pack ref create pointing to baseline commit to succeed: %v", err)
		}
		_ = res.Close()

		_, err = unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(nil),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/copy", OldOID: ZeroOID, NewOID: strings.Repeat("f", 40)}},
			BaselineRepoDir: bare,
		})
		assertDomainErrCode(t, err, "MALFORMED_PACK")
	})

	t.Run("pack_entry_varint_uint64_overflow_rejected", func(t *testing.T) {
		var body bytes.Buffer
		body.WriteString("PACK")
		_ = binary.Write(&body, binary.BigEndian, uint32(2))
		_ = binary.Write(&body, binary.BigEndian, uint32(1))
		// 10-byte varint with shift=60 and upper bit 0x10 set (uint64 overflow).
		body.Write([]byte{0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x10})
		sum := sha1.Sum(body.Bytes())
		body.Write(sum[:])

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(body.Bytes()),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: strings.Repeat("a", 40)}},
		})
		assertDomainErrCode(t, err, "MALFORMED_PACK")
	})

	t.Run("limits_resolve_int64_overflow_guard", func(t *testing.T) {
		resolvedExtreme, err := (Limits{MaxInflatedObjectBytes: 1 << 60}).resolve(defaultLimits())
		if err != nil {
			t.Fatalf("Limits.resolve: %v", err)
		}
		if resolvedExtreme.MaxTotalInflatedBytes != math.MaxInt64 {
			t.Fatalf("MaxTotalInflatedBytes = %d, want %d", resolvedExtreme.MaxTotalInflatedBytes, int64(math.MaxInt64))
		}
		if resolvedExtreme.MaxTotalInflatedBytes < resolvedExtreme.MaxInflatedObjectBytes {
			t.Fatalf("MaxTotalInflatedBytes (%d) < MaxInflatedObjectBytes (%d)", resolvedExtreme.MaxTotalInflatedBytes, resolvedExtreme.MaxInflatedObjectBytes)
		}

		resolvedBaseZero, err := (Limits{MaxInflatedObjectBytes: 1 << 60}).resolve(Limits{MaxInflatedObjectBytes: 1 << 60})
		if err != nil {
			t.Fatalf("Limits.resolve with zero base total: %v", err)
		}
		if resolvedBaseZero.MaxTotalInflatedBytes != math.MaxInt64 {
			t.Fatalf("MaxTotalInflatedBytes = %d, want %d", resolvedBaseZero.MaxTotalInflatedBytes, int64(math.MaxInt64))
		}
	})

	t.Run("workspace_bytes_int64_overflow_guard", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatalf("os.OpenRoot: %v", err)
		}
		defer root.Close()

		wsBytes := int64(math.MaxInt64 - 4)
		err = writeWorkspaceFileBytes(root, "overflow.txt", []byte("0123456789"), math.MaxInt64, &wsBytes)
		assertDomainErrCode(t, err, "WORKSPACE_LIMIT_EXCEEDED")
		if wsBytes != math.MaxInt64-4 {
			t.Fatalf("wsBytes mutated on rejected write: got %d", wsBytes)
		}
	})
}

func TestSpoofedOldOIDHistoryBypassRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	// Build Challenger 1's exact attack pack:
	// c1 introduces a 120000 symlink + secret -> c2 deletes both -> c3 clean tip.
	work := initTestRepo(t, false)
	if err := os.Symlink("/etc/passwd", filepath.Join(work, "evil_sym")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "secret.txt"), []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	runTestGit(t, work, nil, nil, "add", "evil_sym", "secret.txt")
	runTestGit(t, work, nil, nil, "commit", "-m", "c1 add symlink and secret")
	runTestGit(t, work, nil, nil, "rm", "evil_sym", "secret.txt")
	runTestGit(t, work, nil, nil, "commit", "-m", "c2 delete symlink and secret")
	c2 := strings.TrimSpace(runTestGit(t, work, nil, nil, "rev-parse", "HEAD"))
	c3 := commitFile(t, work, "clean.txt", "clean tip\n", "c3 clean tip")

	pack := buildPackFromRevs(t, work, []string{c3}, false)

	t.Run("empty_baseline_repo_spoofed_old_oid_fails_closed", func(t *testing.T) {
		emptyBare := initTestRepo(t, true)
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:       uuid.New(),
			PackReader:          bytes.NewReader(pack),
			RefUpdates:          []RefUpdate{{RefName: "refs/heads/main", OldOID: c2, NewOID: c3}},
			BaselineRepoDir:     emptyBare,
			ExistingRefResolver: nil,
		})
		assertDomainErrCode(t, err, "BASELINE_OBJECT_MISSING")
	})

	t.Run("no_baseline_repo_nonzero_old_oid_fails_closed", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:       uuid.New(),
			PackReader:          bytes.NewReader(pack),
			RefUpdates:          []RefUpdate{{RefName: "refs/heads/main", OldOID: c2, NewOID: c3}},
			BaselineRepoDir:     "",
			ExistingRefResolver: nil,
		})
		assertDomainErrCode(t, err, "BASELINE_OBJECT_MISSING")
	})

	t.Run("non_empty_baseline_repo_spoofed_old_oid_not_in_baseline_fails_closed", func(t *testing.T) {
		otherWork := initTestRepo(t, false)
		_ = commitFile(t, otherWork, "init.txt", "init\n", "init")
		nonEmptyBare := initTestRepo(t, true)
		runTestGit(t, otherWork, nil, nil, "push", nonEmptyBare, "main:refs/heads/main")

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:       uuid.New(),
			PackReader:          bytes.NewReader(pack),
			RefUpdates:          []RefUpdate{{RefName: "refs/heads/main", OldOID: c2, NewOID: c3}},
			BaselineRepoDir:     nonEmptyBare,
			ExistingRefResolver: nil,
		})
		assertDomainErrCode(t, err, "BASELINE_OBJECT_MISSING")
	})

	t.Run("static_baseline_oids_without_baseline_dir_rejects_unlisted_old_oid", func(t *testing.T) {
		cleanWork := initTestRepo(t, false)
		c0 := commitFile(t, cleanWork, "a.txt", "a\n", "c0")
		c1 := commitFile(t, cleanWork, "b.txt", "b\n", "c1")
		c2Clean := commitFile(t, cleanWork, "c.txt", "c\n", "c2")
		standalone := buildPackFromRevs(t, cleanWork, []string{c2Clean}, false)

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(standalone),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2Clean}},
			BaselineOIDs:  []string{c0},
		})
		assertDomainErrCode(t, err, "BASELINE_OBJECT_MISSING")
	})

	t.Run("resolver_without_baseline_dir_allows_cas_verified_old_oid", func(t *testing.T) {
		cleanWork := initTestRepo(t, false)
		c1 := commitFile(t, cleanWork, "a.txt", "a\n", "c1")
		c2Clean := commitFile(t, cleanWork, "b.txt", "b\n", "c2")
		standalone := buildPackFromRevs(t, cleanWork, []string{c2Clean}, false)

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:       uuid.New(),
			PackReader:          bytes.NewReader(standalone),
			RefUpdates:          []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2Clean}},
			ExistingRefResolver: &testRefResolver{refs: map[string]string{"refs/heads/main": c1}},
		})
		if err != nil {
			t.Fatalf("Unpack with CAS-verified resolver failed: %v", err)
		}
		defer res.Close()
		if len(res.Commits) != 1 || res.Commits[0].OID != c2Clean {
			t.Fatalf("Commits = %+v, want only %s", res.Commits, c2Clean)
		}
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})
}

func TestRefDeltaAndMixedDeltaDepthLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	makeCopyAppendDelta := func(base, suffix []byte) ([]byte, []byte) {
		target := append(append([]byte(nil), base...), suffix...)
		var delta bytes.Buffer
		delta.Write(encodeLEB128(uint64(len(base))))
		delta.Write(encodeLEB128(uint64(len(target))))
		delta.WriteByte(0x90)
		delta.WriteByte(byte(len(base)))
		delta.WriteByte(byte(len(suffix)))
		delta.Write(suffix)
		return delta.Bytes(), target
	}

	baseData := []byte("0123456789abcdef")
	baseOID := hashGitObjectRaw("blob", baseData)
	d1Delta, d1Data := makeCopyAppendDelta(baseData, []byte("-1"))
	d1OID := hashGitObjectRaw("blob", d1Data)
	d2Delta, d2Data := makeCopyAppendDelta(d1Data, []byte("-2"))
	d2OID := hashGitObjectRaw("blob", d2Data)
	d3Delta, d3Data := makeCopyAppendDelta(d2Data, []byte("-3"))
	d3OID := hashGitObjectRaw("blob", d3Data)

	treePayload := buildRawTreePayload([]struct {
		mode string
		name string
		oid  [20]byte
	}{
		{mode: "100644", name: "b0.txt", oid: baseOID},
		{mode: "100644", name: "b1.txt", oid: d1OID},
		{mode: "100644", name: "b2.txt", oid: d2OID},
		{mode: "100644", name: "b3.txt", oid: d3OID},
	})
	treeOID := hashGitObjectRaw("tree", treePayload)
	commitPayload := []byte(
		"tree " + fmtHex20(treeOID) + "\n" +
			"author Test <t@e.com> 1700000000 +0000\n" +
			"committer Test <t@e.com> 1700000000 +0000\n\n" +
			"chained delta commit\n",
	)
	commitOID := hashGitObjectRaw("commit", commitPayload)
	commitHex := fmtHex20(commitOID)

	t.Run("multi_hop_ref_delta_chain_enforces_max_delta_depth", func(t *testing.T) {
		refDeltaPack := buildRawPack([]rawPackEntry{
			{objType: packObjCommit, rawPayload: commitPayload, declaredSizeOverride: -1},
			{objType: packObjTree, rawPayload: treePayload, declaredSizeOverride: -1},
			{objType: packObjBlob, rawPayload: baseData, declaredSizeOverride: -1},
			{objType: packObjRefDelta, rawPayload: d1Delta, declaredSizeOverride: -1, refDeltaBase: baseOID},
			{objType: packObjRefDelta, rawPayload: d2Delta, declaredSizeOverride: -1, refDeltaBase: d1OID},
			{objType: packObjRefDelta, rawPayload: d3Delta, declaredSizeOverride: -1, refDeltaBase: d2OID},
		})

		for _, limit := range []int{1, 2} {
			_, err := unpacker.Unpack(ctx, UnpackRequest{
				PushSessionID: uuid.New(),
				PackReader:    bytes.NewReader(refDeltaPack),
				RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: commitHex}},
				Limits:        Limits{MaxDeltaDepth: limit},
			})
			assertDomainErrCode(t, err, "DELTA_DEPTH_LIMIT_EXCEEDED")
		}

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(refDeltaPack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: commitHex}},
			Limits:        Limits{MaxDeltaDepth: 3},
		})
		if err != nil {
			t.Fatalf("expected depth=3 REF_DELTA chain with MaxDeltaDepth=3 to succeed: %v", err)
		}
		defer res.Close()
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})

	t.Run("mixed_ref_delta_and_ofs_delta_chain_enforces_max_delta_depth", func(t *testing.T) {
		// Calculate exact pack offset of d1 (entry index 3) so d2 (entry index 4) can use OBJ_OFS_DELTA referencing d1.
		entriesPrefix := []rawPackEntry{
			{objType: packObjCommit, rawPayload: commitPayload, declaredSizeOverride: -1},
			{objType: packObjTree, rawPayload: treePayload, declaredSizeOverride: -1},
			{objType: packObjBlob, rawPayload: baseData, declaredSizeOverride: -1},
		}
		off := uint64(12)
		for _, e := range entriesPrefix {
			off += uint64(len(encodePackEntryHeader(e.objType, uint64(len(e.rawPayload)))))
			off += uint64(len(compressZlib(e.rawPayload)))
		}
		d1Offset := off
		d1HeaderLen := uint64(len(encodePackEntryHeader(packObjRefDelta, uint64(len(d1Delta)))) + 20 + len(compressZlib(d1Delta)))
		d2Offset := d1Offset + d1HeaderLen
		negOffD2ToD1 := d2Offset - d1Offset

		mixedPack := buildRawPack([]rawPackEntry{
			{objType: packObjCommit, rawPayload: commitPayload, declaredSizeOverride: -1},
			{objType: packObjTree, rawPayload: treePayload, declaredSizeOverride: -1},
			{objType: packObjBlob, rawPayload: baseData, declaredSizeOverride: -1},
			{objType: packObjRefDelta, rawPayload: d1Delta, declaredSizeOverride: -1, refDeltaBase: baseOID},
			{objType: packObjOfsDelta, rawPayload: d2Delta, declaredSizeOverride: -1, ofsDeltaNeg: negOffD2ToD1},
			{objType: packObjRefDelta, rawPayload: d3Delta, declaredSizeOverride: -1, refDeltaBase: d2OID},
		})

		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(mixedPack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: commitHex}},
			Limits:        Limits{MaxDeltaDepth: 2},
		})
		assertDomainErrCode(t, err, "DELTA_DEPTH_LIMIT_EXCEEDED")

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(mixedPack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: commitHex}},
			Limits:        Limits{MaxDeltaDepth: 3},
		})
		if err != nil {
			t.Fatalf("expected depth=3 mixed delta chain with MaxDeltaDepth=3 to succeed: %v", err)
		}
		defer res.Close()
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})

	t.Run("thin_pack_within_max_delta_depth_1_succeeds", func(t *testing.T) {
		work := initTestRepo(t, false)
		c1 := commitFile(t, work, "base.txt", strings.Repeat("baseline content line\n", 20), "base")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		c2 := commitFile(t, work, "base.txt", strings.Repeat("baseline content line\n", 20)+"added line\n", "c2")
		thinPack := buildPackFromRevs(t, work, []string{c2, "^" + c1}, true)

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(thinPack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c1, NewOID: c2}},
			BaselineRepoDir: bare,
			Limits:          Limits{MaxDeltaDepth: 1},
		})
		if err != nil {
			t.Fatalf("expected thin-pack at depth=1 <= MaxDeltaDepth=1 to succeed: %v", err)
		}
		defer res.Close()
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})
}

func fmtHex20(b [20]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 40)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
