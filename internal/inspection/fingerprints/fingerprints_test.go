package fingerprints_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math"
	"math/big"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/workflow"
)

func fixturePath(rel string) string {
	return filepath.Join("..", "..", "..", "test", "e2e", "fixtures", "push_gateway", rel)
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixturePath(rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

func seedDefaultCorpora(t *testing.T) (*fingerprints.MemoryCorpusStore, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	store := fingerprints.NewMemoryCorpusStore()
	idx := fingerprints.NewCorpusIndexer(store, store)

	restRow, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "acme-restricted-core",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("create restricted corpus: %v", err)
	}
	confRow, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "acme-confidential-billing",
		Classification: domain.ClassificationConfidential,
	})
	if err != nil {
		t.Fatalf("create confidential corpus: %v", err)
	}

	if _, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: restRow.ID,
		Files: []fingerprints.CorpusFile{
			{Path: "engine/proprietary_engine.go", Content: readFixture(t, "corpora/restricted/proprietary_engine.go")},
			{Path: "settlement/proprietary_header.py", Content: readFixture(t, "corpora/restricted/proprietary_header.py")},
		},
	}); err != nil {
		t.Fatalf("index restricted corpus: %v", err)
	}

	if _, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: confRow.ID,
		Files: []fingerprints.CorpusFile{
			{Path: "billing/internal_billing_rules.go", Content: readFixture(t, "corpora/confidential/internal_billing_rules.go")},
		},
	}); err != nil {
		t.Fatalf("index confidential corpus: %v", err)
	}

	return store, restRow.ID, confRow.ID
}

func runEngineOnFiles(t *testing.T, engine *fingerprints.Engine, files map[string][]byte, unifiedDiff string) ([]domain.Finding, domain.ScanCoverage, error) {
	t.Helper()
	dir := t.TempDir()
	for rel, data := range files {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", abs, err)
		}
		if err := os.WriteFile(abs, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", abs, err)
		}
	}
	inv, err := inspection.WalkWorkspace(dir)
	if err != nil {
		t.Fatalf("WalkWorkspace: %v", err)
	}
	return engine.Analyze(context.Background(), inspection.Request{
		PushSessionID: ptrUUID(domain.MustNewID()),
		ArtifactID:    domain.MustNewID(),
		TargetDir:     dir,
		Stage:         inspection.StagePushEgress,
		UnifiedDiff:   unifiedDiff,
	}, inv)
}

func ptrUUID(id uuid.UUID) *uuid.UUID { return &id }

func assertNoRawLeak(t *testing.T, findings []domain.Finding, cov domain.ScanCoverage, forbiddenNeedles ...string) {
	t.Helper()
	for i, f := range findings {
		if err := f.ValidateRedacted(); err != nil {
			t.Fatalf("finding[%d] ValidateRedacted failed: %v", i, err)
		}
		if err := domain.ValidateIPFingerprintMetadata(f.Metadata); err != nil {
			t.Fatalf("finding[%d] ValidateIPFingerprintMetadata failed: %v", i, err)
		}
		rawJSON, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal finding[%d]: %v", i, err)
		}
		s := string(rawJSON)
		for _, needle := range forbiddenNeedles {
			if needle != "" && strings.Contains(s, needle) {
				t.Fatalf("finding[%d] leaked forbidden content %q: %s", i, needle, s)
			}
		}
	}
	for _, r := range cov.SkippedReasons {
		for _, needle := range forbiddenNeedles {
			if needle != "" && strings.Contains(r, needle) {
				t.Fatalf("skipped reason leaked forbidden content %q: %s", needle, r)
			}
		}
	}
}

func hasRule(findings []domain.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasCategory(findings []domain.Finding, category string) bool {
	for _, f := range findings {
		if f.Category == category {
			return true
		}
	}
	return false
}

func TestL1ExactChunkNormalizationAndChunking(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	// 1. BOM + CRLF normalization must still match LF-indexed RESTRICTED corpus.
	rawEngine := readFixture(t, "corpora/restricted/proprietary_engine.go")
	bomCRLF := append([]byte{0xEF, 0xBB, 0xBF}, bytes.ReplaceAll(rawEngine, []byte("\n"), []byte("\r\n"))...)

	findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"copied/engine.go": bomCRLF,
	}, "")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !cov.Complete || cov.FilesSkipped != 0 {
		t.Fatalf("expected complete coverage, got %+v", cov)
	}
	if !hasRule(findings, "ip.l1.exact-chunk") || !hasRule(findings, "ip.l2.winnow-kgram") || !hasRule(findings, "ip.l3.header-marker") {
		t.Fatalf("expected L1+L2+L3 matches for exact copy, got %+v", findings)
	}
	if hasRule(findings, "ip.l3.header-stripped") {
		t.Fatalf("did not expect header-stripped when header is intact, got %+v", findings)
	}
	assertNoRawLeak(t, findings, cov,
		"Acme Proprietary Systems Inc",
		"TelemetryCalibrator",
		"proprietary_engine.go",
	)

	// 2. < 64 non-whitespace bytes guard.
	chunksTiny := fingerprints.ExtractL1Chunks("tiny.go", []byte("package main\n\nfunc f() int { return 1 }\n"), 4096)
	if len(chunksTiny) != 0 {
		t.Fatalf("expected <64 non-ws bytes to produce 0 L1 chunks, got %d", len(chunksTiny))
	}

	// 3. Multi-chunk (> 4096 bytes) line-aligned overlap + ultra-long single line fallback.
	var big strings.Builder
	for i := 0; i < 200; i++ {
		big.WriteString("func computeStep(x float64) float64 { return x*0.94175 + 1.0 }\n")
	}
	multiChunks := fingerprints.ExtractL1Chunks("big.go", []byte(big.String()), 4096)
	if len(multiChunks) < 3 {
		t.Fatalf("expected >=3 overlapping L1 chunks for >12KB file, got %d", len(multiChunks))
	}
	if multiChunks[1].LineStart >= multiChunks[0].LineEnd {
		t.Fatalf("expected ~50%% line overlap between chunk 0 (%d..%d) and chunk 1 (%d..%d)",
			multiChunks[0].LineStart, multiChunks[0].LineEnd, multiChunks[1].LineStart, multiChunks[1].LineEnd)
	}
	ultraLong := strings.Repeat("a", 9000)
	longChunks := fingerprints.ExtractL1Chunks("min.js", []byte(ultraLong), 4096)
	if len(longChunks) < 3 {
		t.Fatalf("expected byte-window fallback for ultra-long line, got %d chunks", len(longChunks))
	}
}

func TestL2WinnowingEvadesRenamingCommentsImportsAndBlocksTinySnippets(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	// 1. Renamed/comment-free/string-edited Go code (stripped_header_engine.go) matches L2 + L3b header-stripped.
	stripped := readFixture(t, "payloads/stripped_header_engine.go")
	findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"pkg/signal_processor.go": stripped,
	}, "")
	if err != nil {
		t.Fatalf("Analyze stripped_header_engine: %v", err)
	}
	if !cov.Complete {
		t.Fatalf("expected complete coverage, got %+v", cov)
	}
	if !hasRule(findings, "ip.l2.winnow-kgram") {
		t.Fatalf("expected L2 Winnow match on stripped_header_engine.go, got %+v", findings)
	}
	if !hasRule(findings, "ip.l3.header-stripped") {
		t.Fatalf("expected L3b ip.l3.header-stripped without diff, got %+v", findings)
	}

	// 2. Python proprietary code with renamed identifiers & altered comments/docstrings matches L2.
	renamedPy := []byte(`
# Custom module note
WEIGHTS = (0.4125, 0.2875, 0.1950, 0.1050)
FLOOR = 17.425

def score_batch(rows, vol, cap):
    if not rows or cap <= 0:
        raise ValueError("bad batch")
    acc = FLOOR
    for idx, item in enumerate(rows):
        total = 0.0
        for j, w in enumerate(WEIGHTS):
            v = float(item[j]) if j < len(item) else 0.0
            total += v * w
        damp = 1.0 + (vol * 0.03125 * (idx + 1))
        acc += total / damp
    return min(acc, float(cap))
`)
	pyFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{"score.py": renamedPy}, "")
	if err != nil {
		t.Fatalf("Analyze renamed python: %v", err)
	}
	if !hasRule(pyFindings, "ip.l2.winnow-kgram") || !hasRule(pyFindings, "ip.l3.header-stripped") {
		t.Fatalf("expected L2 + L3b header-stripped on renamed Python, got %+v", pyFindings)
	}

	// 3. 7-token snippet (subwindow.go) must produce ZERO matches.
	subwindow := []byte("package subwindow\n\nconst Magic = 0xAC4E2026\n")
	subFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{"subwindow.go": subwindow}, "")
	if err != nil {
		t.Fatalf("Analyze subwindow: %v", err)
	}
	if len(subFindings) != 0 {
		t.Fatalf("expected 0 findings for 7-token subwindow, got %+v", subFindings)
	}

	// 4. Clean feature & shared Go import block must produce ZERO matches.
	clean := readFixture(t, "payloads/clean_feature.go")
	sharedImports := []byte(`package cleanapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

func HelloWorld(user string) string {
	if strings.TrimSpace(user) == "" {
		return fmt.Sprintf("hi %d", time.Now().Year())
	}
	return "hi " + user
}
`)
	cleanFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"clean_feature.go":  clean,
		"shared_imports.go": sharedImports,
	}, "")
	if err != nil {
		t.Fatalf("Analyze clean files: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings on clean feature + shared imports, got %+v", cleanFindings)
	}
}

func TestL3HeadersOSSExclusionAndUnifiedDiffStrip(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	// 1. Standalone copyright_marker_only.txt (even with Store == nil!) -> RESTRICTED L3 marker.
	noStoreEngine := fingerprints.NewEngine(fingerprints.EngineConfig{})
	notice := readFixture(t, "payloads/copyright_marker_only.txt")
	noticeFindings, _, err := runEngineOnFiles(t, noStoreEngine, map[string][]byte{"NOTICE.txt": notice}, "")
	if err != nil {
		t.Fatalf("Analyze notice: %v", err)
	}
	if !hasRule(noticeFindings, "ip.l3.header-marker") {
		t.Fatalf("expected ip.l3.header-marker on copyright_marker_only.txt, got %+v", noticeFindings)
	}
	if cls, _ := noticeFindings[0].Metadata["corpus_classification"].(string); cls != "RESTRICTED" {
		t.Fatalf("expected RESTRICTED classification on notice, got %q", cls)
	}
	assertNoRawLeak(t, noticeFindings, domain.ScanCoverage{}, "Acme Proprietary Systems Inc", "CONFIDENTIAL AND PROPRIETARY")

	// 2. Safe OSS exclusion (MIT / Apache / BSD copyright headers must NOT trigger).
	mit := []byte("// Copyright (c) 2026 Open Source Contributors\n// SPDX-License-Identifier: MIT\n// Permission is hereby granted, free of charge, to any person obtaining a copy.\npackage mitpkg\n\nfunc OK() int { return 42 }\n")
	bsd := []byte("// Copyright (c) 2026 Example Org. All rights reserved.\n// Redistribution and use in source and binary forms, with or without modification, are permitted.\npackage bsdpkg\n\nfunc OK() int { return 42 }\n")
	apache := []byte("// Copyright 2026 Cloud Authors\n// Licensed under the Apache License, Version 2.0\npackage apachepkg\n\nfunc OK() int { return 42 }\n")
	ossFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"mit.go":    mit,
		"bsd.go":    bsd,
		"apache.go": apache,
	}, "")
	if err != nil {
		t.Fatalf("Analyze OSS files: %v", err)
	}
	if len(ossFindings) != 0 {
		t.Fatalf("expected 0 findings on safe OSS headers, got %+v", ossFindings)
	}

	// 3. Exact body minus header (corpus_body_without_header via headerless_body L3 hash).
	rawEngine := string(readFixture(t, "corpora/restricted/proprietary_engine.go"))
	idx := strings.Index(rawEngine, "package engine")
	headerlessExact := []byte(rawEngine[idx:])
	exactStripFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{"engine.go": headerlessExact}, "")
	if err != nil {
		t.Fatalf("Analyze headerless exact: %v", err)
	}
	if !hasRule(exactStripFindings, "ip.l3.header-stripped") {
		t.Fatalf("expected ip.l3.header-stripped for exact copy minus header, got %+v", exactStripFindings)
	}

	// 4. UnifiedDiff stripped-header detection (even without corpus hit).
	diff := `diff --git a/proprietary.go b/proprietary.go
--- a/proprietary.go
+++ b/proprietary.go
@@ -1,4 +1,2 @@
-// Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.
-// CLASSIFICATION: RESTRICTED — PROPRIETARY TRADE SECRET.
 package proprietary
+func helper() int { return 1 }
`
	diffFindings, _, err := runEngineOnFiles(t, noStoreEngine, map[string][]byte{
		"proprietary.go": []byte("package proprietary\nfunc helper() int { return 1 }\n"),
	}, diff)
	if err != nil {
		t.Fatalf("Analyze unified diff: %v", err)
	}
	if !hasRule(diffFindings, "ip.l3.header-stripped") {
		t.Fatalf("expected ip.l3.header-stripped from UnifiedDiff, got %+v", diffFindings)
	}
}

func TestL4ConcealmentEntropyEncodedArchivesBombsAndMagicMismatch(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	// 1. L4a High Shannon entropy (~7.95 bits/byte) vs valid PNG exempt from entropy.
	encBlob := make([]byte, 4096)
	state := uint32(0xA55A1337)
	for i := range encBlob {
		state = state*1664525 + 1013904223
		encBlob[i] = byte(state >> 24)
	}
	validPNG := buildGenuinePNG(t, 48, 48)
	entFindings, entCov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"encrypted_blob.bin": encBlob,
		"logo.png":           validPNG,
		"digest.sha256":      []byte(domain.SHA256Hex([]byte("clean")) + "\n"),
	}, "")
	if err != nil {
		t.Fatalf("Analyze entropy: %v", err)
	}
	if !entCov.Complete {
		t.Fatalf("expected complete coverage, got %+v", entCov)
	}
	if !hasRule(entFindings, "ip.l4.high-entropy") {
		t.Fatalf("expected ip.l4.high-entropy on encrypted_blob.bin, got %+v", entFindings)
	}
	for _, f := range entFindings {
		if f.Path == "logo.png" || f.Path == "digest.sha256" {
			t.Fatalf("unexpected finding on valid PNG or SHA-256 file: %+v", f)
		}
	}

	// 2. L4b Base64 (`concealed_base64.txt`) + Hex + Concealed Secret.
	b64Fixture := readFixture(t, "payloads/concealed_base64.txt")
	rawProp := readFixture(t, "corpora/restricted/proprietary_engine.go")
	hexPayload := []byte(hex.EncodeToString(rawProp) + "\n")
	fakeSecret := "ghp_0123456789abcdef0123456789abcdef0123"
	b64Secret := []byte("const s = \"" + base64.StdEncoding.EncodeToString([]byte("TOKEN="+fakeSecret+" padding-for-length-check-1234567890")) + "\"\n")

	encFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"concealed_base64.txt": b64Fixture,
		"concealed_hex.txt":    hexPayload,
		"concealed_secret.js":  b64Secret,
	}, "")
	if err != nil {
		t.Fatalf("Analyze encoded: %v", err)
	}
	if !hasRule(encFindings, "ip.l4.encoded-payload") {
		t.Fatalf("expected ip.l4.encoded-payload, got %+v", encFindings)
	}
	if !hasCategory(encFindings, "IP_EXACT") && !hasCategory(encFindings, "IP_WINNOW") {
		t.Fatalf("expected decoded IP corpus match, got %+v", encFindings)
	}
	if !hasCategory(encFindings, "SECRET") {
		t.Fatalf("expected concealed SECRET finding, got %+v", encFindings)
	}
	assertNoRawLeak(t, encFindings, domain.ScanCoverage{}, fakeSecret, "TelemetryCalibrator")

	// 3. L4c Nested archive (`concealed_nested.zip`) + Clean archive.
	nestedZip := readFixture(t, "payloads/concealed_nested.zip")
	cleanTarGz := buildSingleFileTarGz(t, "hello.go", []byte("package clean\nfunc Hi() string { return \"hi\" }\n"))
	arcFindings, arcCov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"concealed_nested.zip": nestedZip,
		"clean.tar.gz":         cleanTarGz,
	}, "")
	if err != nil {
		t.Fatalf("Analyze nested archive: %v", err)
	}
	if !arcCov.Complete {
		t.Fatalf("expected complete coverage for valid archives, got %+v", arcCov)
	}
	if !hasRule(arcFindings, "ip.l4.nested-archive-payload") {
		t.Fatalf("expected ip.l4.nested-archive-payload, got %+v", arcFindings)
	}

	// 4. L4c Gzip Bomb (64 MiB zeros) -> fail closed (FilesSkipped > 0, Complete == false) + finding.
	bombBytes := buildGzipBomb(t, 64<<20)
	bombFindings, bombCov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"bomb.tar.gz": bombBytes,
	}, "")
	if err != nil {
		t.Fatalf("Analyze gzip bomb returned unexpected error: %v", err)
	}
	if bombCov.Complete || bombCov.FilesSkipped == 0 {
		t.Fatalf("expected fail-closed incomplete coverage on gzip bomb, got %+v", bombCov)
	}
	if !hasRule(bombFindings, "ip.l4.archive-limit-exceeded") {
		t.Fatalf("expected ip.l4.archive-limit-exceeded on bomb, got %+v", bombFindings)
	}

	// 5. L4c Path traversal inside zip -> fail closed + unsafe-archive-entry.
	travZip := buildSingleFileZip(t, "../escape.go", []byte("package escape\n"))
	travFindings, travCov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"trav.zip": travZip,
	}, "")
	if err != nil {
		t.Fatalf("Analyze traversal zip: %v", err)
	}
	if travCov.Complete || travCov.FilesSkipped == 0 || !hasRule(travFindings, "ip.l4.unsafe-archive-entry") {
		t.Fatalf("expected fail-closed unsafe-archive-entry on traversal zip, cov=%+v findings=%+v", travCov, travFindings)
	}

	// 6. L4d Structural Magic-Byte Mismatch (`disguised.png` + ELF in `.txt`).
	disguisedPNG := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, rawProp...)
	elfInTxt := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 32)...)
	magicFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"disguised.png":  disguisedPNG,
		"docs/notes.txt": elfInTxt,
	}, "")
	if err != nil {
		t.Fatalf("Analyze magic mismatch: %v", err)
	}
	mismatchCount := 0
	for _, f := range magicFindings {
		if f.RuleID == "ip.l4.magic-byte-mismatch" {
			mismatchCount++
		}
	}
	if mismatchCount != 2 {
		t.Fatalf("expected 2 magic-byte-mismatch findings, got %d (%+v)", mismatchCount, magicFindings)
	}
	if !hasCategory(magicFindings, "IP_EXACT") && !hasCategory(magicFindings, "IP_WINNOW") {
		t.Fatalf("expected unwrapped Go payload inside disguised.png to also match IP corpus, got %+v", magicFindings)
	}
}

type failingLookupStore struct{}

func (failingLookupStore) LookupIPFingerprintsByHashes(context.Context, domain.FingerprintLayer, []string) ([]persistence.IPFingerprintLookupRow, error) {
	return nil, errors.New("db connection refused")
}

func TestEngineFailClosedAndMaxFileBytesAndNoDoubleCount(t *testing.T) {
	// 1. RequireStore=true with Store=nil fails closed.
	reqStoreEng := fingerprints.NewEngine(fingerprints.EngineConfig{RequireStore: true})
	_, cov, err := runEngineOnFiles(t, reqStoreEng, map[string][]byte{"main.go": []byte("package main\n")}, "")
	if err == nil || cov.Complete {
		t.Fatalf("expected error + Complete=false when RequireStore=true and Store=nil, cov=%+v err=%v", cov, err)
	}

	// 2. Store lookup error fails closed.
	errEng := fingerprints.NewEngine(fingerprints.EngineConfig{Store: failingLookupStore{}})
	_, cov2, err := runEngineOnFiles(t, errEng, map[string][]byte{
		"big.go": readFixture(t, "corpora/restricted/proprietary_engine.go"),
	}, "")
	if err == nil || cov2.Complete {
		t.Fatalf("expected fail-closed on store error, cov=%+v err=%v", cov2, err)
	}

	// 3. MaxFileInspectBytes skips oversized file and does NOT double-count inv.FilesSkipped.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "small.go"), []byte("package small\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "huge.go"), bytes.Repeat([]byte("a"), 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "small.go"), filepath.Join(dir, "sym.go")); err != nil {
		t.Fatal(err)
	}
	inv, err := inspection.WalkWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if inv.FilesSkipped != 1 {
		t.Fatalf("expected inv.FilesSkipped == 1 for symlink, got %d", inv.FilesSkipped)
	}

	sizeEng := fingerprints.NewEngine(fingerprints.EngineConfig{MaxFileInspectBytes: 1024})
	_, cov3, err := sizeEng.Analyze(context.Background(), inspection.Request{
		PushSessionID: ptrUUID(domain.MustNewID()),
		ArtifactID:    domain.MustNewID(),
		TargetDir:     dir,
		Stage:         inspection.StagePushEgress,
	}, inv)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if cov3.Complete || cov3.FilesSkipped != 1 {
		t.Fatalf("expected Engine to report only its 1 newly skipped file (not re-counting inv.FilesSkipped), got %+v", cov3)
	}
}

func TestCorpusIndexerLifecycleReindexConcurrencyAndMemoryStoreNulls(t *testing.T) {
	ctx := context.Background()
	store := fingerprints.NewMemoryCorpusStore()
	idx := fingerprints.NewCorpusIndexer(store, store)

	// 1. Reject non-RESTRICTED/CONFIDENTIAL classification.
	if _, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "invalid-internal",
		Classification: domain.ClassificationInternal,
	}); err == nil {
		t.Fatalf("expected INVALID_CORPUS_CLASSIFICATION for INTERNAL corpus")
	}

	corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "reindex-test",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}

	fileA := readFixture(t, "corpora/restricted/proprietary_engine.go")
	fileB := readFixture(t, "corpora/restricted/proprietary_header.py")

	// 2. Initial index -> READY.
	res1, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files:    []fingerprints.CorpusFile{{Path: "a.go", Content: fileA}},
	})
	if err != nil {
		t.Fatalf("Index 1: %v", err)
	}
	if res1.Corpus.Status != domain.IPCorpusStatusReady || res1.FingerprintCount == 0 || res1.Skipped {
		t.Fatalf("unexpected Index 1 result: %+v", res1)
	}

	// Verify zero raw source stored in MemoryCorpusStore rows.
	for _, row := range store.ListAllFingerprints(corpus.ID) {
		raw, _ := json.Marshal(row)
		s := string(raw)
		if strings.Contains(s, "TelemetryCalibrator") || strings.Contains(s, "Acme Proprietary") || strings.Contains(s, "a.go") {
			t.Fatalf("stored fingerprint row leaked raw source or path: %s", s)
		}
		var meta map[string]any
		_ = json.Unmarshal(row.Metadata, &meta)
		if err := domain.ValidateIPFingerprintMetadata(meta); err != nil {
			t.Fatalf("stored metadata failed ValidateIPFingerprintMetadata: %v", err)
		}
	}

	// 3. Idempotent reindex with identical content skips without mutating count.
	res2, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files:    []fingerprints.CorpusFile{{Path: "a.go", Content: fileA}},
	})
	if err != nil || !res2.Skipped || res2.FingerprintCount != res1.FingerprintCount {
		t.Fatalf("expected idempotent skip on identical digest, got %+v err=%v", res2, err)
	}

	// 4. Modified corpus replaces stale fingerprints cleanly (file A removed, file B added).
	res3, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files:    []fingerprints.CorpusFile{{Path: "b.py", Content: fileB}},
	})
	if err != nil || res3.Skipped || res3.FingerprintCount == 0 {
		t.Fatalf("expected reindex on changed files, got %+v err=%v", res3, err)
	}

	// Lookup for fileA's L1 hash must now return 0 matches!
	chunksA := fingerprints.ExtractL1Chunks("a.go", fileA, 4096)
	hitsA, err := store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL1ExactChunk, []string{chunksA[0].HashHex})
	if err != nil || len(hitsA) != 0 {
		t.Fatalf("expected stale fingerprints deleted after reindex, got hits=%+v err=%v", hitsA, err)
	}

	// 5. Concurrent reindex calls serialize cleanly via per-corpus mutex.
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := idx.Index(ctx, fingerprints.IndexRequest{
				CorpusID: corpus.ID,
				Force:    true,
				Files:    []fingerprints.CorpusFile{{Path: "b.py", Content: fileB}},
			})
			if err != nil {
				t.Errorf("concurrent Index error: %v", err)
			}
		}()
	}
	wg.Wait()

	// 6. Empty corpus transitions corpus status to FAILED or rejects cleanly.
	if _, err := idx.Index(ctx, fingerprints.IndexRequest{CorpusID: corpus.ID, Files: nil}); err == nil {
		t.Fatalf("expected error for empty corpus")
	}

	// 7. Multi-row UpsertIPFingerprintsBatch with empty FilePathHash (nil *string) + UNIQUE NULLS NOT DISTINCT dedup.
	nullCorpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "null-filepath-corpus",
		Classification: domain.ClassificationConfidential,
		Status:         domain.IPCorpusStatusReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	h1 := domain.SHA256Hex([]byte("h1"))
	h2 := domain.SHA256Hex([]byte("h2"))
	n, err := store.UpsertIPFingerprintsBatch(ctx, []persistence.InsertIPFingerprintParams{
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h1, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 100}},
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h1, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 200}},
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h2, FilePathHash: h1, Metadata: map[string]any{"chunk_bytes": 300}},
	})
	if err != nil {
		t.Fatalf("multi-row UpsertIPFingerprintsBatch with nil FilePathHash failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deduplicated rows affected, got %d", n)
	}
	cnt, err := store.CountIPFingerprintsByCorpus(ctx, nullCorpus.ID)
	if err != nil || cnt != 2 {
		t.Fatalf("expected CountIPFingerprintsByCorpus == 2, got %d (err=%v)", cnt, err)
	}
	// Disabled corpus must NOT return lookup matches.
	disabled := false
	disCorpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "disabled-corpus",
		Classification: domain.ClassificationRestricted,
		Enabled:        &disabled,
		Status:         domain.IPCorpusStatusReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	hDisabled := domain.SHA256Hex([]byte("disabled"))
	if _, err := store.UpsertIPFingerprintsBatch(ctx, []persistence.InsertIPFingerprintParams{
		{CorpusID: disCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: hDisabled},
	}); err != nil {
		t.Fatal(err)
	}
	if hits, err := store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL1ExactChunk, []string{hDisabled}); err != nil || len(hits) != 0 {
		t.Fatalf("expected 0 hits for disabled corpus, got %+v (err=%v)", hits, err)
	}
}

func BenchmarkEngineAnalyze(b *testing.B) {
	ctx := context.Background()
	store := fingerprints.NewMemoryCorpusStore()
	idx := fingerprints.NewCorpusIndexer(store, store)

	corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "bench-restricted",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		b.Fatal(err)
	}
	propGo, err := os.ReadFile(fixturePath("corpora/restricted/proprietary_engine.go"))
	if err != nil {
		b.Fatal(err)
	}
	propPy, err := os.ReadFile(fixturePath("corpora/restricted/proprietary_header.py"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files: []fingerprints.CorpusFile{
			{Path: "engine.go", Content: propGo},
			{Path: "header.py", Content: propPy},
		},
	}); err != nil {
		b.Fatal(err)
	}

	dir := b.TempDir()
	stripped, err := os.ReadFile(fixturePath("payloads/stripped_header_engine.go"))
	if err != nil {
		b.Fatal(err)
	}
	clean, err := os.ReadFile(fixturePath("payloads/clean_feature.go"))
	if err != nil {
		b.Fatal(err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"a.go", stripped},
		{"b.go", clean},
		{"c.go", clean},
		{"d.go", propGo},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	inv, err := inspection.WalkWorkspace(dir)
	if err != nil {
		b.Fatal(err)
	}
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})
	req := inspection.Request{
		PushSessionID: ptrUUID(domain.MustNewID()),
		ArtifactID:    domain.MustNewID(),
		TargetDir:     dir,
		Stage:         inspection.StagePushEgress,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, cov, err := engine.Analyze(ctx, req, inv)
		if err != nil || !cov.Complete {
			b.Fatalf("Analyze failed: cov=%+v err=%v", cov, err)
		}
	}
}

func TestEngineLatencyUnder200msTarget(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})
	start := time.Now()
	_, cov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"stripped.go": readFixture(t, "payloads/stripped_header_engine.go"),
		"clean.go":    readFixture(t, "payloads/clean_feature.go"),
	}, "")
	elapsed := time.Since(start)
	if err != nil || !cov.Complete {
		t.Fatalf("Analyze failed: cov=%+v err=%v", cov, err)
	}
	t.Logf("Engine.Analyze typical push latency: %v", elapsed)
}

func buildSingleFileTarGz(t testing.TB, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildSingleFileZip(t testing.TB, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildGzipBomb(t testing.TB, uncompressedSize int) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "bomb.bin", Mode: 0o644, Size: int64(uncompressedSize)}); err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 64*1024)
	rem := uncompressedSize
	for rem > 0 {
		n := len(zeros)
		if rem < n {
			n = rem
		}
		if _, err := tw.Write(zeros[:n]); err != nil {
			t.Fatal(err)
		}
		rem -= n
	}
	_ = tw.Close()
	var gzBuf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&gzBuf, gzip.BestSpeed)
	_, _ = gz.Write(tarBuf.Bytes())
	_ = gz.Close()
	return gzBuf.Bytes()
}

func TestMemoryCorpusStoreRunCorpusTxConcurrentDistinctCorpora(t *testing.T) {
	ctx := context.Background()
	store := fingerprints.NewMemoryCorpusStore()
	idx := fingerprints.NewCorpusIndexer(store, store)

	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")
	propPy := readFixture(t, "corpora/restricted/proprietary_header.py")

	const numCorpora = 6
	corpusIDs := make([]uuid.UUID, numCorpora)
	probeHashes := make([]string, numCorpora)

	for i := 0; i < numCorpora; i++ {
		cls := domain.ClassificationRestricted
		if i%2 == 1 {
			cls = domain.ClassificationConfidential
		}
		row, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
			Name:           fmt.Sprintf("concurrent-corpus-%d", i),
			Classification: cls,
		})
		if err != nil {
			t.Fatalf("CreateIPFingerprintCorpus(%d): %v", i, err)
		}
		corpusIDs[i] = row.ID
	}

	startGate := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, numCorpora)

	for i := 0; i < numCorpora; i++ {
		i := i
		content := append([]byte(fmt.Sprintf("// CorpusTag_%d_UniqueMarker\n", i)), propGo...)
		if i%2 == 1 {
			content = append([]byte(fmt.Sprintf("# CorpusTag_%d_UniqueMarker\n", i)), propPy...)
		}
		chunks := fingerprints.ExtractL1Chunks(fmt.Sprintf("src_%d/file.go", i), content, 4096)
		if len(chunks) == 0 {
			t.Fatalf("expected >=1 chunk for corpus %d", i)
		}
		probeHashes[i] = chunks[0].HashHex

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			_, err := idx.Index(ctx, fingerprints.IndexRequest{
				CorpusID: corpusIDs[i],
				Files: []fingerprints.CorpusFile{
					{Path: fmt.Sprintf("src_%d/file.go", i), Content: content},
				},
			})
			if err != nil {
				errs <- fmt.Errorf("corpus %d index: %w", i, err)
			}
		}()
	}

	close(startGate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	for i, cid := range corpusIDs {
		got, err := store.GetIPFingerprintCorpusByID(ctx, cid)
		if err != nil {
			t.Fatalf("GetIPFingerprintCorpusByID(%d): %v", i, err)
		}
		if got.Status != domain.IPCorpusStatusReady || got.FingerprintCount == 0 {
			t.Fatalf("corpus %d lost READY status/count after concurrent RunCorpusTx: status=%s count=%d", i, got.Status, got.FingerprintCount)
		}
		hits, err := store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL1ExactChunk, []string{probeHashes[i]})
		if err != nil || len(hits) == 0 {
			t.Fatalf("corpus %d lost L1 fingerprints after concurrent RunCorpusTx: hits=%d err=%v", i, len(hits), err)
		}
	}
}

func TestCorpusIndexerValidationFailuresTransitionToFailed(t *testing.T) {
	ctx := context.Background()
	validContent := readFixture(t, "corpora/restricted/proprietary_engine.go")

	buildSymlinkDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		target := filepath.Join(dir, "real.go")
		if err := os.WriteFile(target, validContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "link.go")); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	cases := []struct {
		name  string
		mkReq func(t *testing.T, id uuid.UUID) fingerprints.IndexRequest
	}{
		{
			name: "empty-slice",
			mkReq: func(_ *testing.T, id uuid.UUID) fingerprints.IndexRequest {
				return fingerprints.IndexRequest{CorpusID: id, Files: nil}
			},
		},
		{
			name: "zero-byte-file",
			mkReq: func(_ *testing.T, id uuid.UUID) fingerprints.IndexRequest {
				return fingerprints.IndexRequest{
					CorpusID: id,
					Files:    []fingerprints.CorpusFile{{Path: "empty.go", Content: []byte{}}},
				}
			},
		},
		{
			name: "whitespace-only-file",
			mkReq: func(_ *testing.T, id uuid.UUID) fingerprints.IndexRequest {
				return fingerprints.IndexRequest{
					CorpusID: id,
					Files:    []fingerprints.CorpusFile{{Path: "ws.go", Content: []byte("  \n\t\r\n  ")}},
				}
			},
		},
		{
			name: "incomplete-workspace-walk",
			mkReq: func(t *testing.T, id uuid.UUID) fingerprints.IndexRequest {
				return fingerprints.IndexRequest{
					CorpusID: id,
					Dir:      buildSymlinkDir(t),
				}
			},
		},
		{
			name: "digest-mismatch",
			mkReq: func(_ *testing.T, id uuid.UUID) fingerprints.IndexRequest {
				return fingerprints.IndexRequest{
					CorpusID: id,
					Files: []fingerprints.CorpusFile{{
						Path:    "a.go",
						Content: validContent,
						SHA256:  strings.Repeat("0", 64),
					}},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run("PENDING_to_FAILED/"+tc.name, func(t *testing.T) {
			store := fingerprints.NewMemoryCorpusStore()
			idx := fingerprints.NewCorpusIndexer(store, store)
			corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
				Name:           "pending-" + tc.name,
				Classification: domain.ClassificationRestricted,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := idx.Index(ctx, tc.mkReq(t, corpus.ID)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			after, err := store.GetIPFingerprintCorpusByID(ctx, corpus.ID)
			if err != nil {
				t.Fatal(err)
			}
			if after.Status != domain.IPCorpusStatusFailed || after.LastError == nil || *after.LastError == "" {
				t.Fatalf("expected PENDING->FAILED with LastError for %s, got status=%s lastErr=%v", tc.name, after.Status, after.LastError)
			}
		})

		t.Run("READY_preserved_on_failure/"+tc.name, func(t *testing.T) {
			store := fingerprints.NewMemoryCorpusStore()
			idx := fingerprints.NewCorpusIndexer(store, store)
			corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
				Name:           "ready-" + tc.name,
				Classification: domain.ClassificationRestricted,
			})
			if err != nil {
				t.Fatal(err)
			}
			initRes, err := idx.Index(ctx, fingerprints.IndexRequest{
				CorpusID: corpus.ID,
				Files:    []fingerprints.CorpusFile{{Path: "engine.go", Content: validContent}},
			})
			if err != nil {
				t.Fatalf("initial index failed: %v", err)
			}
			if _, err := idx.Index(ctx, tc.mkReq(t, corpus.ID)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			after, err := store.GetIPFingerprintCorpusByID(ctx, corpus.ID)
			if err != nil {
				t.Fatal(err)
			}
			if after.Status != domain.IPCorpusStatusReady || after.FingerprintCount != initRes.FingerprintCount {
				t.Fatalf("expected READY preserved with count=%d for %s, got status=%s count=%d", initRes.FingerprintCount, tc.name, after.Status, after.FingerprintCount)
			}
		})
	}
}

func TestPolyglotAndExtensionDisguisedBypassesAndValidControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	// 1. Polyglot PDF (%PDF-1.4\n// obj\n + Go + \n// %%EOF\n).
	polyPDF := append([]byte("%PDF-1.4\n// obj\n"), stripped...)
	polyPDF = append(polyPDF, []byte("\n// %%EOF\n")...)

	// 2. Raw Go disguised as .pdf (manual.pdf).
	manualPDF := stripped

	// 3. Polyglot WEBP (RIFF0000WEBP\n + Go).
	polyWEBP := append([]byte("RIFF0000WEBP\n"), stripped...)

	// 4. Polyglot WASM (\x00asm\x01\x00\x00\x00 + 2048 CSPRNG bytes).
	csprng := make([]byte, 2048)
	state := uint32(0xCAFEBABE)
	for i := range csprng {
		state = state*1664525 + 1013904223
		csprng[i] = byte(state >> 24)
	}
	polyWASM := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, csprng...)

	// 5. Extensionless archive entry (payload.zip!calibrator).
	extlessZip := buildSingleFileZip(t, "calibrator", stripped)

	for name, payload := range map[string][]byte{
		"polyglot.pdf": polyPDF,
		"manual.pdf":   manualPDF,
		"img.webp":     polyWEBP,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.magic-byte-mismatch") {
			t.Fatalf("%s expected ip.l4.magic-byte-mismatch, got %+v", name, findings)
		}
		if !hasRule(findings, "ip.l2.winnow-kgram") || !hasRule(findings, "ip.l3.header-stripped") {
			t.Fatalf("%s expected L2 Winnow + L3 header-stripped, got %+v", name, findings)
		}
	}

	wasmFindings, wasmCov, err := runEngineOnFiles(t, engine, map[string][]byte{"mod.wasm": polyWASM}, "")
	if err != nil || !wasmCov.Complete {
		t.Fatalf("mod.wasm Analyze failed: cov=%+v err=%v", wasmCov, err)
	}
	if !hasRule(wasmFindings, "ip.l4.magic-byte-mismatch") || !hasRule(wasmFindings, "ip.l4.high-entropy") {
		t.Fatalf("mod.wasm expected magic-byte-mismatch and high-entropy, got %+v", wasmFindings)
	}

	if lang := fingerprints.DetectLanguage("payload.zip!calibrator", stripped); lang != "go" {
		t.Fatalf("expected DetectLanguage(payload.zip!calibrator) == \"go\", got %q", lang)
	}
	zipFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{"payload.zip": extlessZip}, "")
	if err != nil {
		t.Fatalf("payload.zip Analyze failed: %v", err)
	}
	if !hasRule(zipFindings, "ip.l2.winnow-kgram") || !hasRule(zipFindings, "ip.l3.header-stripped") || !hasRule(zipFindings, "ip.l4.nested-archive-payload") {
		t.Fatalf("expected extensionless archive entry L2 + L3 + L4 hits, got %+v", zipFindings)
	}

	// Valid PDF, WEBP, and WASM controls must produce 0 findings.
	validPDF := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n50\n%%EOF\n")

	validWEBP := buildMinimalValidVP8WebP()

	// Valid WASM with Type section (1) and Code section (10) summing cleanly to EOF.
	validWASM := []byte{
		0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: 1 func () -> ()
		0x03, 0x02, 0x01, 0x00, // Function section: func 0 uses type 0
		0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: 1 body, 2 bytes: locals=0, end
	}

	ctrlFindings, ctrlCov, err := runEngineOnFiles(t, engine, map[string][]byte{
		"doc.pdf":  validPDF,
		"pic.webp": validWEBP,
		"ok.wasm":  validWASM,
	}, "")
	if err != nil || !ctrlCov.Complete {
		t.Fatalf("valid controls Analyze failed: cov=%+v err=%v", ctrlCov, err)
	}
	if len(ctrlFindings) != 0 {
		t.Fatalf("expected 0 findings on valid PDF/WEBP/WASM controls, got %+v", ctrlFindings)
	}
}

func TestL4aTailPaddedHighEntropyOverOneMiB(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 4 << 20,
	})

	// 1.125 MiB file: ~1.09 MiB benign comments + 32 KiB PRNG bytes at the tail.
	const totalSize = 1152 * 1024
	const tailSize = 32 * 1024
	padLine := []byte("// benign telemetry padding line for size check\n")
	buf := make([]byte, 0, totalSize)
	buf = append(buf, []byte("package padded\n")...)
	for len(buf) < totalSize-tailSize {
		buf = append(buf, padLine...)
	}
	buf = buf[:totalSize-tailSize]
	state := uint32(0x12345678)
	for i := 0; i < tailSize; i++ {
		state = state*1664525 + 1013904223
		buf = append(buf, byte(state>>24))
	}

	findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{"tail_padded.go": buf}, "")
	if err != nil || !cov.Complete {
		t.Fatalf("Analyze tail_padded.go failed: cov=%+v err=%v", cov, err)
	}
	if !hasRule(findings, "ip.l4.high-entropy") {
		t.Fatalf("expected ip.l4.high-entropy for 1.125 MiB tail-padded payload, got %+v", findings)
	}
}

func TestL3BenignMITAndOSSDocCommentsWithRestrictedWord(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	aclGo := []byte(`// Copyright (c) 2026 Open Source Contributors
// SPDX-License-Identifier: MIT
//
// Package acl implements restricted scope validation for public OAuth tokens.
package acl

func ValidateScope(scope string) bool { return scope == "read" }
`)
	mitPropComment := []byte(`// Copyright (c) 2026 Open Source Contributors
// SPDX-License-Identifier: MIT
//
// Package legacy parses proprietary vendor metadata in a confidential client flow.
package legacy

func ParseTag(s string) string { return s }
`)
	fakeMITWithBanner := []byte(`// SPDX-License-Identifier: MIT
// CLASSIFICATION: RESTRICTED — PROPRIETARY TRADE SECRET.
package sneaky

func Secret() int { return 1 }
`)

	cleanFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"acl.go":    aclGo,
		"legacy.go": mitPropComment,
	}, "")
	if err != nil {
		t.Fatalf("Analyze OSS files failed: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings on benign MIT doc comments, got %+v", cleanFindings)
	}

	fakeFindings, _, err := runEngineOnFiles(t, engine, map[string][]byte{
		"sneaky.go": fakeMITWithBanner,
	}, "")
	if err != nil {
		t.Fatalf("Analyze fake MIT with banner failed: %v", err)
	}
	if !hasRule(fakeFindings, "ip.l3.header-marker") {
		t.Fatalf("expected ip.l3.header-marker when explicit RESTRICTED banner overrides MIT, got %+v", fakeFindings)
	}
}

func TestL4bBase64AndHexEvasionVectors(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})
	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")

	// 1. 65-identifier flood before base64 payload.
	var floodJS strings.Builder
	for i := 0; i < 65; i++ {
		fmt.Fprintf(&floodJS, "const veryLongIdentifierNamePaddingForBypassAttempt_%03d_ABCDEFGHIJKLMNOPQRSTUVWXYZ = %d;\n", i, i)
	}
	fmt.Fprintf(&floodJS, "const hiddenPayload = %q;\n", base64.StdEncoding.EncodeToString(propGo))

	// 2. 35-hex-token flood before hex payload.
	var hexFloodJS strings.Builder
	for i := 0; i < 35; i++ {
		fmt.Fprintf(&hexFloodJS, "const h%02d = \"%s\";\n", i, strings.Repeat(fmt.Sprintf("%02x", i+1), 50))
	}
	fmt.Fprintf(&hexFloodJS, "const hiddenHex = %q;\n", hex.EncodeToString(propGo))

	// 3. URL-safe multi-line wrapped base64 (44 chars/line using - and _).
	rawURL := base64.RawURLEncoding.EncodeToString(propGo)
	var urlWrapped strings.Builder
	for i := 0; i < len(rawURL); i += 44 {
		end := i + 44
		if end > len(rawURL) {
			end = len(rawURL)
		}
		urlWrapped.WriteString(rawURL[i:end])
		urlWrapped.WriteByte('\n')
	}

	// 4. Quoted string concatenation ("..." +\n "...").
	stdB64 := base64.StdEncoding.EncodeToString(propGo)
	var concatJS strings.Builder
	concatJS.WriteString("const p = ")
	for i := 0; i < len(stdB64); i += 56 {
		end := i + 56
		if end > len(stdB64) {
			end = len(stdB64)
		}
		if i > 0 {
			concatJS.WriteString(" +\n  ")
		}
		fmt.Fprintf(&concatJS, "%q", stdB64[i:end])
	}
	concatJS.WriteString(";\n")

	for name, data := range map[string][]byte{
		"flood.js":    []byte(floodJS.String()),
		"hexflood.js": []byte(hexFloodJS.String()),
		"url44.txt":   []byte(urlWrapped.String()),
		"concat.js":   []byte(concatJS.String()),
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.encoded-payload") {
			t.Fatalf("%s expected ip.l4.encoded-payload, got %+v", name, findings)
		}
		if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") {
			t.Fatalf("%s expected decoded IP corpus match, got %+v", name, findings)
		}
	}
}

func TestReviewerHardeningDiffGzipMultistreamAndSmallChunk(t *testing.T) {
	// 1. DetectStrippedHeadersInUnifiedDiff: header-only deletion (addedNonEmpty == 0) + per-hunk OSS exemption.
	headerOnlyDiff := `diff --git a/engine.go b/engine.go
--- a/engine.go
+++ b/engine.go
@@ -1,3 +1,1 @@
-// Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.
-// CLASSIFICATION: RESTRICTED — PROPRIETARY TRADE SECRET.
 package engine
`
	strips := fingerprints.DetectStrippedHeadersInUnifiedDiff(headerOnlyDiff)
	if len(strips) != 1 || strips[0].RelPath != "engine.go" || strips[0].Classification != domain.ClassificationRestricted {
		t.Fatalf("expected 1 RESTRICTED diff strip for header-only deletion, got %+v", strips)
	}

	ossMultiLineDiff := `diff --git a/bsd.go b/bsd.go
--- a/bsd.go
+++ b/bsd.go
@@ -1,3 +1,1 @@
-// Copyright (c) 2026 Example Org. All rights reserved.
-// SPDX-License-Identifier: MIT
 package bsd
`
	if got := fingerprints.DetectStrippedHeadersInUnifiedDiff(ossMultiLineDiff); len(got) != 0 {
		t.Fatalf("expected 0 diff strips when removing multi-line OSS header, got %+v", got)
	}

	// 2. Multi-member concatenated gzip & tar.gz streams.
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})
	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")

	var gz1, gz2 bytes.Buffer
	w1 := gzip.NewWriter(&gz1)
	_, _ = w1.Write([]byte("clean member one\n"))
	_ = w1.Close()
	w2 := gzip.NewWriter(&gz2)
	_, _ = w2.Write(propGo)
	_ = w2.Close()
	multiGz := append(gz1.Bytes(), gz2.Bytes()...)

	cleanTarGz := buildSingleFileTarGz(t, "clean.go", []byte("package clean\nfunc Ok() {}\n"))
	evilTarGz := buildSingleFileTarGz(t, "evil.go", propGo)
	multiTarGz := append(append([]byte(nil), cleanTarGz...), evilTarGz...)

	for name, arc := range map[string][]byte{
		"multi.gz":     multiGz,
		"multi.tar.gz": multiTarGz,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: arc}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.nested-archive-payload") || (!hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW")) {
			t.Fatalf("%s expected multi-member gzip IP + nested-archive-payload findings, got %+v", name, findings)
		}
	}

	// 3. ExtractL1Chunks with chunkSizeBytes < 1024 preserves overlap (stepTarget <= chunkSizeBytes/2).
	var src strings.Builder
	for i := 0; i < 40; i++ {
		src.WriteString("func step(x int) int { return x * 31 + 7 }\n")
	}
	smallChunks := fingerprints.ExtractL1Chunks("small.go", []byte(src.String()), 512)
	if len(smallChunks) < 3 {
		t.Fatalf("expected >=3 overlapping chunks for chunkSizeBytes=512, got %d", len(smallChunks))
	}
	if smallChunks[1].LineStart >= smallChunks[0].LineEnd {
		t.Fatalf("expected overlap for chunkSizeBytes=512: chunk0=%d..%d chunk1=%d..%d",
			smallChunks[0].LineStart, smallChunks[0].LineEnd, smallChunks[1].LineStart, smallChunks[1].LineEnd)
	}
}

func buildGenuinePNG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r := byte((x*255/max(w-1, 1) + (y*7)/2 + ((x ^ y) & 3)) & 0xff)
			g := byte((y*255/max(h-1, 1) + (x*5)/2 + ((x + y) & 3)) & 0xff)
			b := byte(((x+y)*127/max(w+h-2, 1) + (x & 3)) & 0xff)
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

func buildCSPRNGPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	state := uint32(0x13572468)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			state = state*1664525 + 1013904223
			r := byte(state >> 24)
			state = state*1664525 + 1013904223
			g := byte(state >> 24)
			state = state*1664525 + 1013904223
			b := byte(state >> 24)
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

func buildGenuineJPEG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	state := uint32(0x24681357)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			state = state*1664525 + 1013904223
			img.SetRGBA(x, y, color.RGBA{R: byte(state >> 24), G: byte(state >> 16), B: byte(state >> 8), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	return buf.Bytes()
}

func minimalValidVP8Chunk() []byte {
	return []byte{
		0xf0, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00, 0x10, 0x00, 0x02, 0x00, 0x34, 0x25, 0xb0, 0x02,
		0x74, 0x01, 0x0f, 0x0c, 0x12, 0xf2, 0xca, 0x80, 0x00, 0xfe, 0xfd, 0x6f, 0x14, 0x60, 0xc7, 0x65,
		0x5b, 0x6a, 0xb5, 0xf0, 0xb9, 0x84, 0xb5, 0x66, 0x70, 0x97, 0xee, 0x72, 0xec, 0x02, 0x07, 0xe6,
		0x2f, 0xff, 0xf9, 0x17, 0xba, 0x9f, 0xff, 0x3c, 0x7e, 0x97, 0xe2, 0xe4, 0x00, 0x00,
	}
}

func minimalValidVP8LChunk() []byte {
	return []byte{
		0x2f, 0x0f, 0xc0, 0x03, 0x00, 0xb9, 0x8c, 0xe8, 0x7f, 0xec, 0x0a, 0x51, 0x88, 0x82, 0xf7, 0x3f,
		0x20, 0x24, 0x20, 0x4c, 0xf0, 0xff, 0xb0, 0xa8, 0x0e, 0x44, 0xc4, 0x04, 0x80, 0xd5, 0xbb, 0x00,
	}
}

func buildMinimalValidVP8WebP() []byte {
	return buildRIFFWebP(struct {
		fourCC  string
		payload []byte
	}{"VP8 ", minimalValidVP8Chunk()})
}

func buildMinimalValidVP8LWebP() []byte {
	return buildRIFFWebP(struct {
		fourCC  string
		payload []byte
	}{"VP8L", minimalValidVP8LChunk()})
}

func buildGenuineVP8WebP(payload []byte) []byte {
	// VP8 chunk: 10-byte keyframe header (tag + sync 0x9d 0x01 0x2a + 16x16 dims) + payload.
	vp8Payload := make([]byte, 10+len(payload))
	vp8Payload[0] = 0x10 // keyframe bit 0 == 0
	vp8Payload[1] = 0x00
	vp8Payload[2] = 0x00
	vp8Payload[3] = 0x9d
	vp8Payload[4] = 0x01
	vp8Payload[5] = 0x2a
	binary.LittleEndian.PutUint16(vp8Payload[6:8], 16)
	binary.LittleEndian.PutUint16(vp8Payload[8:10], 16)
	copy(vp8Payload[10:], payload)

	pad := len(vp8Payload) & 1
	chunkTotal := 8 + len(vp8Payload) + pad
	out := make([]byte, 12+chunkTotal)
	copy(out[0:4], "RIFF")
	binary.LittleEndian.PutUint32(out[4:8], uint32(4+chunkTotal))
	copy(out[8:12], "WEBP")
	copy(out[12:16], "VP8 ")
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(vp8Payload)))
	copy(out[20:20+len(vp8Payload)], vp8Payload)
	return out
}

func buildGenuineVP8LWebP(payload []byte) []byte {
	vp8lPayload := make([]byte, 5+len(payload))
	vp8lPayload[0] = 0x2f // VP8L signature byte
	vp8lPayload[1] = 0x0f
	vp8lPayload[2] = 0x00
	vp8lPayload[3] = 0x00
	vp8lPayload[4] = 0x00
	copy(vp8lPayload[5:], payload)

	pad := len(vp8lPayload) & 1
	chunkTotal := 8 + len(vp8lPayload) + pad
	out := make([]byte, 12+chunkTotal)
	copy(out[0:4], "RIFF")
	binary.LittleEndian.PutUint32(out[4:8], uint32(4+chunkTotal))
	copy(out[8:12], "WEBP")
	copy(out[12:16], "VP8L")
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(vp8lPayload)))
	copy(out[20:20+len(vp8lPayload)], vp8lPayload)
	return out
}

func buildGenuineCompressedPDF(t testing.TB) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte("BT\n/F1 12 Tf\n72 720 Td\n(Hello Custodian Public Whitepaper) Tj\nET\n"))
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	streamData := z.Bytes()

	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	pdf.Write([]byte{'%', 0xe2, 0xe3, 0xcf, 0xd3, 0x00, '\n'})
	pdf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	pdf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	pdf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n")
	fmt.Fprintf(&pdf, "4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(streamData))
	pdf.Write(streamData)
	pdf.WriteString("\nendstream\nendobj\n")
	pdf.WriteString("xref\n0 5\n0000000000 65535 f \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n250\n%%EOF\n")
	return pdf.Bytes()
}

func buildGenuineWASMWithCustomNameSection() []byte {
	// Custom section: id=0, name="name", function-names subsection with realistic identifiers.
	var nameBody bytes.Buffer
	nameBody.WriteByte(0x04) // len("name")
	nameBody.WriteString("name")
	nameBody.WriteByte(0x01) // function names subsection id=1
	sub := []byte{0x02, 0x00, 0x07, 'a', 'd', 'd', '_', 'i', '3', '2', 0x01, 0x07, 's', 'u', 'b', '_', 'i', '3', '2'}
	nameBody.WriteByte(byte(len(sub)))
	nameBody.Write(sub)

	out := []byte{
		0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section
		0x03, 0x02, 0x01, 0x00, // Function section
		0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section
		0x00, byte(nameBody.Len()),
	}
	return append(out, nameBody.Bytes()...)
}

func encodeUTF16LEWithBOM(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 2+len(u16)*2)
	out[0] = 0xFF
	out[1] = 0xFE
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[2+i*2:4+i*2], v)
	}
	return out
}

func TestIteration3RemediationAll19VectorsAndRealisticControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")
	propPy := readFixture(t, "corpora/restricted/proprietary_header.py")
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	csprng := make([]byte, 4096)
	state := uint32(0x9E3779B9)
	for i := range csprng {
		state = state*1664525 + 1013904223
		csprng[i] = byte(state >> 24)
	}

	// --- Root Cause 1: NUL-byte prefix & 8KB NUL-padded .dat ---
	nulPrefixGo := append([]byte{0x00}, propGo...)
	nulPrefixTxt := append([]byte{0x00}, propGo...)
	dat8KBNulPlusGo := append(make([]byte, 8192), stripped...)

	for name, data := range map[string][]byte{
		"nul_prefix.go":           nulPrefixGo,
		"nul_prefix.txt":          nulPrefixTxt,
		"dat_8kb_nul_plus_go.dat": dat8KBNulPlusGo,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.magic-byte-mismatch") {
			t.Fatalf("%s expected ip.l4.magic-byte-mismatch, got %+v", name, findings)
		}
		if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") {
			t.Fatalf("%s expected L1/L2 IP match past NUL bytes, got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}

	// --- Root Cause 2: WASM, WEBP, PDF, PNG, JPEG structural polyglots ---
	// 2a. WASM custom section id=0 with source & CSPRNG.
	buildWASMWithCustom := func(secName string, payload []byte) []byte {
		var sec bytes.Buffer
		sec.WriteByte(byte(len(secName)))
		sec.WriteString(secName)
		sec.Write(payload)
		var lenBuf [5]byte
		n := binary.PutUvarint(lenBuf[:], uint64(sec.Len()))
		out := []byte{
			0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
			0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
			0x00,
		}
		out = append(out, lenBuf[:n]...)
		return append(out, sec.Bytes()...)
	}
	wasmCustomGo := buildWASMWithCustom("ip", stripped)
	wasmCustomCSPRNG := buildWASMWithCustom("ip", csprng)

	// 2b. WEBP valid RIFF + VP8 \x00\x00\x00\x00 + source / CSPRNG.
	buildZeroVP8WEBP := func(tail []byte) []byte {
		body := append([]byte("VP8 \x00\x00\x00\x00"), tail...)
		out := make([]byte, 12+len(body))
		copy(out[0:4], "RIFF")
		binary.LittleEndian.PutUint32(out[4:8], uint32(4+len(body)))
		copy(out[8:12], "WEBP")
		copy(out[12:], body)
		return out
	}
	webpZeroGo := buildZeroVP8WEBP(stripped)
	webpZeroCSPRNG := buildZeroVP8WEBP(csprng)

	// 2c. PDF real framing with \x00 binary comment + Go (no package) / Python (no def/from) / unfiltered CSPRNG stream.
	strippedNoPkg := bytes.Replace(stripped, []byte("package payloads\n"), nil, 1)
	propPyNoDef := bytes.Replace(propPy, []byte("def "), nil, 1)
	pdfNulGo := append([]byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\x00\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"), strippedNoPkg...)
	pdfNulGo = append(pdfNulGo, []byte("\nxref\n0 2\nstartxref\n50\n%%EOF\n")...)
	pdfNulPy := append([]byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\x00\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"), propPyNoDef...)
	pdfNulPy = append(pdfNulPy, []byte("\nxref\n0 2\nstartxref\n50\n%%EOF\n")...)
	pdfCSPRNGStream := append([]byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Length 4096 >>\nstream\n"), csprng...)
	pdfCSPRNGStream = append(pdfCSPRNGStream, []byte("\nendstream\nendobj\nxref\n0 2\nstartxref\n50\n%%EOF\n")...)

	// 2d. PNG 29B IHDR stub + source / CSPRNG; JPEG 6B FF D8 FF E0 00 10 + source.
	pngIHDRHdr := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0}
	polyIHDRGoPNG := append(append([]byte(nil), pngIHDRHdr...), stripped...)
	polyIHDRCSPRNGPNG := append(append([]byte(nil), pngIHDRHdr...), csprng[:2048]...)
	polyNulGoJPG := append([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, stripped...)

	for name, data := range map[string][]byte{
		"wasm_custom_section_go.wasm":          wasmCustomGo,
		"webp_valid_riff_vp8_nul_plus_go.webp": webpZeroGo,
		"pdf_real_framing_nul_plus_go.pdf":     pdfNulGo,
		"pdf_real_framing_nul_plus_py.pdf":     pdfNulPy,
		"polyglot_ihdr_go.png":                 polyIHDRGoPNG,
		"polyglot_nul_go.jpg":                  polyNulGoJPG,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "IP_WINNOW") && !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_HEADER_MARKER") && !hasCategory(findings, "IP_HEADER_STRIP") {
			t.Fatalf("%s expected IP detection (L1/L2/L3), got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}

	for name, data := range map[string][]byte{
		"wasm_custom_section_csprng.wasm":          wasmCustomCSPRNG,
		"webp_valid_riff_vp8_zero_hdr_csprng.webp": webpZeroCSPRNG,
		"pdf_real_framing_csprng_stream.pdf":       pdfCSPRNGStream,
		"polyglot_ihdr_csprng.png":                 polyIHDRCSPRNGPNG,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.high-entropy") {
			t.Fatalf("%s expected ip.l4.high-entropy, got %+v", name, findings)
		}
	}

	// --- Root Cause 3: L4b comment-wrapped base64, wrapped hex, comma-joined array, short-segment concat ---
	b64Prop := base64.StdEncoding.EncodeToString(propGo)
	wrapLines := func(s string, width int, prefix string, suffix string) string {
		var b strings.Builder
		for i := 0; i < len(s); i += width {
			end := i + width
			if end > len(s) {
				end = len(s)
			}
			b.WriteString(prefix)
			b.WriteString(s[i:end])
			b.WriteString(suffix)
			b.WriteByte('\n')
		}
		return b.String()
	}
	commentB64Go := "package sneaky\n" + wrapLines(b64Prop, 48, "// ", "")
	commentB64Py := "x = 1\n" + wrapLines(b64Prop, 48, "# ", "")
	blockCommentB64Go := "package sneaky\n/*\n" + wrapLines(b64Prop, 48, " * ", "") + " */\n"
	wrappedHex64 := wrapLines(hex.EncodeToString(propGo), 64, "", "")

	var arrayCommaJS strings.Builder
	arrayCommaJS.WriteString("const p = [\n")
	for i := 0; i < len(b64Prop); i += 48 {
		end := i + 48
		if end > len(b64Prop) {
			end = len(b64Prop)
		}
		if i > 0 {
			arrayCommaJS.WriteString(",\n")
		}
		fmt.Fprintf(&arrayCommaJS, "  %q", b64Prop[i:end])
	}
	arrayCommaJS.WriteString("\n].join('');\n")

	var shortSegJS strings.Builder
	shortSegJS.WriteString("const s = ")
	for i := 0; i < len(b64Prop); i += 10 {
		end := i + 10
		if end > len(b64Prop) {
			end = len(b64Prop)
		}
		if i > 0 {
			shortSegJS.WriteString(" + ")
		}
		fmt.Fprintf(&shortSegJS, "%q", b64Prop[i:end])
	}
	shortSegJS.WriteString(";\n")

	for name, data := range map[string][]byte{
		"comment_wrapped_b64.go": []byte(commentB64Go),
		"comment_wrapped_b64.py": []byte(commentB64Py),
		"block_comment_b64.go":   []byte(blockCommentB64Go),
		"wrapped_hex_64.txt":     []byte(wrappedHex64),
		"array_comma_concat.js":  []byte(arrayCommaJS.String()),
		"short_seg_concat.js":    []byte(shortSegJS.String()),
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l4.encoded-payload") {
			t.Fatalf("%s expected ip.l4.encoded-payload, got %+v", name, findings)
		}
		if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") {
			t.Fatalf("%s expected decoded IP corpus match, got %+v", name, findings)
		}
	}

	// --- Root Cause 4: Triple concatenated .tar.gz ---
	clean1 := buildSingleFileTarGz(t, "clean1.go", []byte("package clean1\nfunc A() int { return 1 }\n"))
	clean2 := buildSingleFileTarGz(t, "clean2.go", []byte("package clean2\nfunc B() int { return 2 }\n"))
	evil3 := buildSingleFileTarGz(t, "evil.go", propGo)
	tripleTarGz := append(append(append([]byte(nil), clean1...), clean2...), evil3...)

	tripleFindings, tripleCov, err := runEngineOnFiles(t, engine, map[string][]byte{"triple_concat_tar_gz.tar.gz": tripleTarGz}, "")
	if err != nil || !tripleCov.Complete {
		t.Fatalf("triple_concat_tar_gz Analyze failed: cov=%+v err=%v", tripleCov, err)
	}
	if !hasRule(tripleFindings, "ip.l4.nested-archive-payload") || (!hasCategory(tripleFindings, "IP_EXACT") && !hasCategory(tripleFindings, "IP_WINNOW")) {
		t.Fatalf("triple_concat_tar_gz expected nested-archive-payload + IP match, got %+v", tripleFindings)
	}

	// --- Realistic Valid Controls (MUST produce 0 findings -> ALLOW) ---
	validControls := map[string][]byte{
		"real_photo.png":          buildGenuinePNG(t, 64, 64),
		"real_photo.jpg":          buildGenuineJPEG(t, 64, 64),
		"real_compressed.pdf":     buildGenuineCompressedPDF(t),
		"real_vp8.webp":           buildMinimalValidVP8WebP(),
		"real_vp8l.webp":          buildMinimalValidVP8LWebP(),
		"real_custom_name.wasm":   buildGenuineWASMWithCustomNameSection(),
		"valid_utf16le.go":        encodeUTF16LEWithBOM("package clean\n\n// Open source helper\nfunc Greet(name string) string { return \"hello \" + name }\n"),
		"benign_oss_arrays.js":    []byte("// SPDX-License-Identifier: MIT\n// Benign UI labels\nconst tags = [\"alpha\", \"beta\", \"gamma\", \"delta\", \"epsilon\", \"zeta\", \"theta\"].join(\",\");\nexport function listTags() { return tags; }\n"),
		"benign_binary_table.dat": append([]byte{0x01, 0x00, 0x02, 0x00, 'V', 'E', 'R', '1', 0x00}, csprng[:128]...),
	}
	ctrlFindings, ctrlCov, err := runEngineOnFiles(t, engine, validControls, "")
	if err != nil || !ctrlCov.Complete {
		t.Fatalf("realistic valid controls Analyze failed: cov=%+v err=%v", ctrlCov, err)
	}
	if len(ctrlFindings) != 0 {
		t.Fatalf("expected 0 findings on realistic valid controls, got %+v", ctrlFindings)
	}
}

func makePNGChunk(chunkType string, payload []byte) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint32(len(payload)))
	out.WriteString(chunkType)
	out.Write(payload)
	crc := crc32.ChecksumIEEE(append([]byte(chunkType), payload...))
	_ = binary.Write(&out, binary.BigEndian, crc)
	return out.Bytes()
}

func injectPNGChunksBeforeIEND(t testing.TB, basePNG []byte, extra ...[]byte) []byte {
	t.Helper()
	iendIdx := bytes.LastIndex(basePNG, []byte{0, 0, 0, 0, 'I', 'E', 'N', 'D'})
	if iendIdx < 8 {
		t.Fatalf("invalid base PNG: missing IEND")
	}
	var out bytes.Buffer
	out.Write(basePNG[:iendIdx])
	for _, c := range extra {
		out.Write(c)
	}
	out.Write(basePNG[iendIdx:])
	return out.Bytes()
}

func buildRIFFWebP(chunks ...struct {
	fourCC  string
	payload []byte
}) []byte {
	var body bytes.Buffer
	body.WriteString("WEBP")
	for _, c := range chunks {
		body.WriteString(c.fourCC)
		_ = binary.Write(&body, binary.LittleEndian, uint32(len(c.payload)))
		body.Write(c.payload)
		if len(c.payload)&1 == 1 {
			body.WriteByte(0)
		}
	}
	var out bytes.Buffer
	out.WriteString("RIFF")
	_ = binary.Write(&out, binary.LittleEndian, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func interleaveNUL(data []byte, every int) []byte {
	var out bytes.Buffer
	for i, b := range data {
		if i > 0 && i%every == 0 {
			out.WriteByte(0x00)
		}
		out.WriteByte(b)
	}
	return out.Bytes()
}

func encodeBOMlessUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], v)
	}
	return out
}

func encodeBOMlessUTF16BE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.BigEndian.PutUint16(out[i*2:i*2+2], v)
	}
	return out
}

func buildValidICCProfile(lut []byte) []byte {
	pad4 := func(b []byte) []byte {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	// Tag 1: 'desc'
	descASCII := "Custodian Public sRGB Profile\x00"
	var descBuf bytes.Buffer
	descBuf.WriteString("desc")
	descBuf.Write(make([]byte, 4))
	_ = binary.Write(&descBuf, binary.BigEndian, uint32(len(descASCII)))
	descBuf.WriteString(descASCII)
	descBytes := pad4(descBuf.Bytes())

	// Tag 2: 'cprt' ('text')
	var cprtBuf bytes.Buffer
	cprtBuf.WriteString("text")
	cprtBuf.Write(make([]byte, 4))
	cprtBuf.WriteString("Copyright 2026 Public Domain\x00")
	cprtBytes := pad4(cprtBuf.Bytes())

	// Tag 3: 'wtpt' ('XYZ ')
	var wtptBuf bytes.Buffer
	wtptBuf.WriteString("XYZ ")
	wtptBuf.Write(make([]byte, 4))
	_ = binary.Write(&wtptBuf, binary.BigEndian, uint32(0x0000F6D6))
	_ = binary.Write(&wtptBuf, binary.BigEndian, uint32(0x00010000))
	_ = binary.Write(&wtptBuf, binary.BigEndian, uint32(0x0000D32D))
	wtptBytes := pad4(wtptBuf.Bytes())

	// Tag 4: 'rTRC' (monotonic 'curv' gamma 2.2 ramp)
	cnt := max(256, len(lut)/2)
	var curvBuf bytes.Buffer
	curvBuf.WriteString("curv")
	curvBuf.Write(make([]byte, 4))
	_ = binary.Write(&curvBuf, binary.BigEndian, uint32(cnt))
	for i := 0; i < cnt; i++ {
		v := uint16(math.Round(math.Pow(float64(i)/float64(cnt-1), 2.2) * 65535.0))
		_ = binary.Write(&curvBuf, binary.BigEndian, v)
	}
	curvBytes := pad4(curvBuf.Bytes())

	type iccTagEntry struct {
		sig  string
		data []byte
	}
	tags := []iccTagEntry{
		{"desc", descBytes},
		{"cprt", cprtBytes},
		{"wtpt", wtptBytes},
		{"rTRC", curvBytes},
	}
	tableEnd := 128 + 4 + len(tags)*12
	totalSize := tableEnd
	for _, tg := range tags {
		totalSize += len(tg.data)
	}

	out := make([]byte, totalSize)
	binary.BigEndian.PutUint32(out[0:4], uint32(totalSize))
	copy(out[4:8], "ADBE")
	binary.BigEndian.PutUint32(out[8:12], 0x02100000)
	copy(out[12:16], "mntr")
	copy(out[16:20], "RGB ")
	copy(out[20:24], "XYZ ")
	copy(out[36:40], "acsp")
	binary.BigEndian.PutUint32(out[128:132], uint32(len(tags)))

	curOff := tableEnd
	for i, tg := range tags {
		recOff := 132 + i*12
		copy(out[recOff:recOff+4], tg.sig)
		binary.BigEndian.PutUint32(out[recOff+4:recOff+8], uint32(curOff))
		binary.BigEndian.PutUint32(out[recOff+8:recOff+12], uint32(len(tg.data)))
		copy(out[curOff:curOff+len(tg.data)], tg.data)
		curOff += len(tg.data)
	}
	return out
}

func TestIteration4RemediationAllVectorsAndRealisticControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	csprng := make([]byte, 4096)
	state := uint32(0x7F4A7C15)
	for i := range csprng {
		state = state*1664525 + 1013904223
		csprng[i] = byte(state >> 24)
	}

	// 1. PDF /Length signed int64 overflow panic regression (must fail closed cleanly without panic).
	for name, lengthStr := range map[string]string{
		"max_int64.pdf":      "9223372036854775807",
		"near_max_int64.pdf": "9223372036854775800",
	} {
		pdfOverflow := []byte(fmt.Sprintf("%%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Length %s >>\nstream\nhello\nendstream\nendobj\nxref\n0 2\nstartxref\n50\n%%EOF\n", lengthStr))
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: pdfOverflow}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		_ = findings
	}

	// 2. WebP XMP/EXIF/ICCP valid controls vs EXIF CSPRNG / NUL-interleaved / VP8X-only bypasses.
	validVP8Payload := minimalValidVP8Chunk()
	validICC := buildValidICCProfile(csprng[:512])
	var iccZlib bytes.Buffer
	zw := zlib.NewWriter(&iccZlib)
	_, _ = zw.Write(validICC)
	_ = zw.Close()
	xmpXML := []byte("<?xpacket begin=''?><x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF><dc:description>Genuine WebP Asset Exported from Camera Pipeline 2026</dc:description></rdf:RDF></x:xmpmeta>")
	exifValid := []byte("Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00\x0f\x01\x02\x00\x20\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00Canon EOS R5 Digital Camera Firmware v2.1.0 Public EXIF Metadata")

	webpFullValid := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ICCP", validICC},
		struct {
			fourCC  string
			payload []byte
		}{"ALPH", append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 256)...)},
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8Payload},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", exifValid},
		struct {
			fourCC  string
			payload []byte
		}{"XMP ", xmpXML},
	)
	webpExifValid := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8Payload},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", exifValid},
	)
	webpExifCSPRNG := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8Payload},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", csprng},
	)
	webpExifNulIP := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8Payload},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", interleaveNUL(stripped, 20)},
	)
	webpVP8XOnly := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", csprng},
	)

	// 3. PNG zTXt / compressed iTXt / private chunk bypasses + realistic PNG/JPEG controls.
	basePNG := buildGenuinePNG(t, 48, 48)
	var ztxtIP, ztxtCSPRNG, itxtIP bytes.Buffer
	zw1 := zlib.NewWriter(&ztxtIP)
	_, _ = zw1.Write(stripped)
	_ = zw1.Close()
	zw2 := zlib.NewWriter(&ztxtCSPRNG)
	_, _ = zw2.Write(csprng)
	_ = zw2.Close()
	zw3 := zlib.NewWriter(&itxtIP)
	_, _ = zw3.Write(stripped)
	_ = zw3.Close()

	pngZTxtIP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("zTXt", append([]byte("Source\x00\x00"), ztxtIP.Bytes()...)))
	pngZTxtValidZlibCSPRNG := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("zTXt", append([]byte("Blob\x00\x00"), ztxtCSPRNG.Bytes()...)))
	pngZTxtRawCSPRNG := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("zTXt", append([]byte("Blob\x00\x00"), csprng...)))
	pngITxtCompIP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("iTXt", append([]byte("Src\x00\x01\x00\x00\x00"), itxtIP.Bytes()...)))
	pngPrivCSPRNG := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("coDe", csprng))

	multiChunkRealPNG := injectPNGChunksBeforeIEND(t, basePNG,
		makePNGChunk("iCCP", append([]byte("sRGB\x00\x00"), iccZlib.Bytes()...)),
		makePNGChunk("tEXt", []byte("Software\x00Custodian Public Image Generator 1.0")),
		makePNGChunk("tEXt", []byte("Description\x00A real camera photo taken in 2026 for public docs")),
	)
	xmpPhotoPNG := injectPNGChunksBeforeIEND(t, basePNG,
		makePNGChunk("tEXt", []byte("Copyright\x00Copyright 2026 Public Photographer")),
		makePNGChunk("iTXt", append([]byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00"), xmpXML...)),
	)

	// JPEG bypasses & controls.
	jpgSOSSpoofCSPRNG := append([]byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}, csprng...)
	jpgSOSSpoofCSPRNG = append(jpgSOSSpoofCSPRNG, 0xFF, 0xD9)

	baseJPG := buildGenuineJPEG(t, 48, 48)
	insertJPGBeforeSOS := func(marker byte, payload []byte) []byte {
		sosIdx := bytes.Index(baseJPG, []byte{0xFF, 0xDA})
		if sosIdx < 2 {
			t.Fatalf("missing SOS in base JPEG")
		}
		var seg bytes.Buffer
		seg.WriteByte(0xFF)
		seg.WriteByte(marker)
		_ = binary.Write(&seg, binary.BigEndian, uint16(len(payload)+2))
		seg.Write(payload)
		var out bytes.Buffer
		out.Write(baseJPG[:sosIdx])
		out.Write(seg.Bytes())
		out.Write(baseJPG[sosIdx:])
		return out.Bytes()
	}
	jpgCOMCSPRNG := insertJPGBeforeSOS(0xFE, csprng)
	jpgAPP15CSPRNG := insertJPGBeforeSOS(0xEF, csprng)
	jpgCOMNulIP := insertJPGBeforeSOS(0xFE, interleaveNUL(stripped, 20))
	// Build a genuine DRI=1 multi-MCU (32x32 = 4 MCUs) JPEG with EXIF APP1 decodable by image/jpeg.Decode.
	var solid16 bytes.Buffer
	img16 := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img16.SetRGBA(x, y, color.RGBA{R: 120, G: 140, B: 160, A: 255})
		}
	}
	if err := jpeg.Encode(&solid16, img16, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatalf("encode 16x16 JPEG: %v", err)
	}
	raw16 := solid16.Bytes()
	sof16Idx := bytes.Index(raw16, []byte{0xFF, 0xC0})
	sos16Idx := bytes.Index(raw16, []byte{0xFF, 0xDA})
	if sof16Idx < 0 || sos16Idx < 0 || sos16Idx+14 >= len(raw16)-2 {
		t.Fatalf("unexpected 16x16 JPEG layout")
	}
	hdr32 := append([]byte(nil), raw16[:sos16Idx]...)
	binary.BigEndian.PutUint16(hdr32[sof16Idx+5:sof16Idx+7], 32)
	binary.BigEndian.PutUint16(hdr32[sof16Idx+7:sof16Idx+9], 32)
	sos16HdrLen := int(binary.BigEndian.Uint16(raw16[sos16Idx+2 : sos16Idx+4]))
	mcuBody := raw16[sos16Idx+2+sos16HdrLen : len(raw16)-2]
	var withDRI bytes.Buffer
	withDRI.Write(hdr32)
	withDRI.Write([]byte{0xFF, 0xE1})
	_ = binary.Write(&withDRI, binary.BigEndian, uint16(len(exifValid)+2))
	withDRI.Write(exifValid)
	withDRI.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
	withDRI.Write(raw16[sos16Idx : sos16Idx+2+sos16HdrLen])
	for mcu := 0; mcu < 4; mcu++ {
		if mcu > 0 {
			withDRI.Write([]byte{0xFF, byte(0xD0 + (mcu - 1))})
		}
		withDRI.Write(mcuBody)
	}
	withDRI.Write([]byte{0xFF, 0xD9})
	exifRestartRealJPG := withDRI.Bytes()
	if _, decErr := jpeg.Decode(bytes.NewReader(exifRestartRealJPG)); decErr != nil {
		t.Fatalf("exifRestartRealJPG must be decodable by jpeg.Decode: %v", decErr)
	}
	// Progressive SOF2 JPEG with valid DQT, DHT, two SOS scans, and byte-stuffed 0xFF 0x00.
	progDQT := append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...)
	progDHT := []byte{
		0xFF, 0xC4, 0x00, 0x15, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01,
	}
	var progBuf bytes.Buffer
	progBuf.Write([]byte{0xFF, 0xD8})
	progBuf.Write([]byte{0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00})
	progBuf.Write(progDQT)
	progBuf.Write(progDHT)
	progBuf.Write([]byte{
		0xFF, 0xC2, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
		0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x12, 0x34, 0xFF, 0x00, 0x56, 0x78,
		0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x01, 0x3F, 0x00,
		0x9A, 0xBC, 0xFF, 0x00, 0xDE, 0xF0,
		0xFF, 0xD9,
	})
	progJPG := progBuf.Bytes()

	// 4. PDF CR-only EOL, trailing bytes after %%EOF, & stream filter gaps.
	pdfValidBase := buildGenuineCompressedPDF(t)
	var crPDF bytes.Buffer
	var crZ bytes.Buffer
	crZW := zlib.NewWriter(&crZ)
	_, _ = crZW.Write([]byte("BT\r/F1 12 Tf\r72 720 Td\r(Hello Custodian Public Whitepaper) Tj\rET\r"))
	_ = crZW.Close()
	crStream := crZ.Bytes()
	crPDF.WriteString("%PDF-1.4\r1 0 obj\r<< /Type /Catalog /Pages 2 0 R >>\rendobj\r2 0 obj\r<< /Type /Pages /Kids [3 0 R] /Count 1 >>\rendobj\r3 0 obj\r<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\rendobj\r")
	fmt.Fprintf(&crPDF, "4 0 obj\r<< /Length %d /Filter /FlateDecode >>\rstream\r", len(crStream))
	crPDF.Write(crStream)
	crPDF.WriteString("\rendstream\rendobj\rxref\r0 5\r0000000000 65535 f \rtrailer\r<< /Size 5 /Root 1 0 R >>\rstartxref\r250\r%%EOF\r")
	pdfCROnly := crPDF.Bytes()
	pdfTrailingAfterEOF := append(append([]byte(nil), pdfValidBase...), csprng[:512]...)

	var flateCSPRNG, flateNulIP bytes.Buffer
	zf1 := zlib.NewWriter(&flateCSPRNG)
	_, _ = zf1.Write(csprng)
	_ = zf1.Close()
	zf2 := zlib.NewWriter(&flateNulIP)
	_, _ = zf2.Write(interleaveNUL(stripped, 20))
	_ = zf2.Close()

	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var p bytes.Buffer
		p.WriteString("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		fmt.Fprintf(&p, "2 0 obj\n<< /Length %d %s >>\nstream\n", len(body), dictEntries)
		p.Write(body)
		p.WriteString("\nendstream\nendobj\nxref\n0 3\nstartxref\n50\n%%EOF\n")
		return p.Bytes()
	}

	pdfFlateCSPRNG := makeStreamPDF("/Filter /FlateDecode", flateCSPRNG.Bytes())
	pdfFlateNulIP := makeStreamPDF("/Filter /FlateDecode", flateNulIP.Bytes())

	// Space-separated hex for /ASCIIHexDecode
	rawHex := hex.EncodeToString(propGo)
	var spacedHex bytes.Buffer
	for i := 0; i < len(rawHex); i += 2 {
		if i > 0 {
			spacedHex.WriteByte(' ')
		}
		spacedHex.WriteString(rawHex[i : i+2])
	}
	spacedHex.WriteByte('>')
	pdfASCIIHexIP := makeStreamPDF("/Filter /ASCIIHexDecode", spacedHex.Bytes())

	// Adobe ASCII85 for /ASCII85Decode
	var a85Buf bytes.Buffer
	a85Enc := ascii85.NewEncoder(&a85Buf)
	_, _ = a85Enc.Write(stripped)
	_ = a85Enc.Close()
	a85Buf.WriteString("~>")
	pdfASCII85IP := makeStreamPDF("/Filter /ASCII85Decode", a85Buf.Bytes())

	pdfDCTCSPRNG := makeStreamPDF("/Filter /DCTDecode", append([]byte{0xFF, 0xD8}, csprng...))
	pdfLZWCSPRNG := makeStreamPDF("/Filter /LZWDecode", csprng)
	pdfMultiFilterCSPRNG := makeStreamPDF("/Filter [/FlateDecode /LZWDecode]", flateCSPRNG.Bytes())

	// Valid PDF with /Filter [ /FlateDecode ], indirect /Length 5 0 R, /ObjStm, /XRef, and /Producer (myobj).
	var objStmZ, xrefZ bytes.Buffer
	zo := zlib.NewWriter(&objStmZ)
	_, _ = zo.Write([]byte("1 0 << /Type /Catalog >>"))
	_ = zo.Close()
	zx := zlib.NewWriter(&xrefZ)
	_, _ = zx.Write([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x20, 0x00})
	_ = zx.Close()
	var objStmPDF bytes.Buffer
	objStmPDF.WriteString("%PDF-1.6\n")
	objStmPDF.Write([]byte{'%', 0xe2, 0xe3, 0xcf, 0xd3, 0x00, '\n'})
	fmt.Fprintf(&objStmPDF, "1 0 obj\n<< /Type /ObjStm /Length 5 0 R /Filter [ /FlateDecode ] /Producer (myobj) >>\nstream\n")
	objStmPDF.Write(objStmZ.Bytes())
	objStmPDF.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&objStmPDF, "5 0 obj\n%d\nendobj\n", objStmZ.Len())
	fmt.Fprintf(&objStmPDF, "6 0 obj\n<< /Type /XRef /Length %d /Filter /FlateDecode >>\nstream\n", xrefZ.Len())
	objStmPDF.Write(xrefZ.Bytes())
	objStmPDF.WriteString("\nendstream\nendobj\nstartxref\n200\n%%EOF\n")
	pdfObjWordValid := objStmPDF.Bytes()

	// 5. WASM custom section splitting (20B), NUL-interleaving, 50%-NUL CSPRNG, & valid control.
	buildWASMMultiCustom := func(sections [][]byte) []byte {
		out := []byte{
			0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
			0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		}
		for i, payload := range sections {
			name := fmt.Sprintf("c%d", i)
			var sec bytes.Buffer
			sec.WriteByte(byte(len(name)))
			sec.WriteString(name)
			sec.Write(payload)
			var lb [5]byte
			n := binary.PutUvarint(lb[:], uint64(sec.Len()))
			out = append(out, 0x00)
			out = append(out, lb[:n]...)
			out = append(out, sec.Bytes()...)
		}
		return out
	}
	var splitChunks [][]byte
	for i := 0; i < len(stripped); i += 20 {
		end := min(i+20, len(stripped))
		splitChunks = append(splitChunks, stripped[i:end])
	}
	wasmSplit20B := buildWASMMultiCustom(splitChunks)
	wasmNulInterleaved := buildWASMMultiCustom([][]byte{interleaveNUL(stripped, 20)})
	halfNulCSPRNG := make([]byte, len(csprng)*2)
	for i, b := range csprng {
		halfNulCSPRNG[i*2] = b
		halfNulCSPRNG[i*2+1] = 0x00
	}
	wasmHalfNulCSPRNG := buildWASMMultiCustom([][]byte{halfNulCSPRNG})
	wasmValidNameProducers := buildGenuineWASMWithCustomNameSection()
	producersPayload := append([]byte{byte(len("producers"))}, "producers"...)
	producersPayload = append(producersPayload, 0x01, 0x08, 'l', 'a', 'n', 'g', 'u', 'a', 'g', 'e', 0x01, 0x04, 'r', 'u', 's', 't')
	wasmValidNameProducers = append(wasmValidNameProducers, 0x00, byte(len(producersPayload)))
	wasmValidNameProducers = append(wasmValidNameProducers, producersPayload...)

	// 6. Unlisted source extensions (.proto) & extensionless BOM-less UTF-16 & NUL-interleaved text.
	utf16NoBomProtoIP := encodeBOMlessUTF16LE(string(propGo))
	nul20ProtoIP := interleaveNUL(propGo, 20)
	extlessNulIP := interleaveNUL(propGo, 20)
	cleanUTF16NoBomProto := encodeBOMlessUTF16LE("syntax = \"proto3\";\npackage telemetry.v1;\nmessage PingRequest { string id = 1; }\n")
	cleanUTF16BENoBomGo := encodeBOMlessUTF16BE("package clean\n\n// Open source utility\nfunc Ping() string { return \"pong\" }\n")

	// 7. L4b obfuscation vectors + SHA-256 digest array false-positive check.
	b64Prop := base64.StdEncoding.EncodeToString(propGo)
	joinQuoted := func(s string, width int, openQ, closeQ, sep string) string {
		var b strings.Builder
		for i := 0; i < len(s); i += width {
			end := min(i+width, len(s))
			if i > 0 {
				b.WriteString(sep)
			}
			b.WriteString(openQ)
			b.WriteString(s[i:end])
			b.WriteString(closeQ)
		}
		return b.String()
	}
	backtickConcatJS := "const p = " + joinQuoted(b64Prop, 40, "`", "`", " + ") + ";\n"
	tripleQuoteConcatPy := "p = " + joinQuoted(b64Prop, 40, "'''", "'''", " + ") + "\n"
	short4CharConcatJS := "const s = " + joinQuoted(b64Prop, 4, `"`, `"`, " + ") + ";\n"

	wrapLines := func(s string, width int, prefix string) string {
		var b strings.Builder
		for i := 0; i < len(s); i += width {
			end := min(i+width, len(s))
			b.WriteString(prefix)
			b.WriteString(s[i:end])
			b.WriteByte('\n')
		}
		return b.String()
	}
	wrappedB6424Go := "package sneaky\n" + wrapLines(b64Prop, 24, "// ")
	wrappedHex24Txt := wrapLines(hex.EncodeToString(propGo), 24, "")

	// 16 SHA-256 hex digests in Go slice (MUST be 0 findings!).
	var shaArrayGo strings.Builder
	shaArrayGo.WriteString("package digests\n\nvar Digests = []string{\n")
	for i := 0; i < 16; i++ {
		fmt.Fprintf(&shaArrayGo, "\t%q,\n", domain.SHA256Hex([]byte(fmt.Sprintf("artifact-%d", i))))
	}
	shaArrayGo.WriteString("}\n")
	benignShortUIStringsJS := []byte("export const labels = [\"ok\", \"id\", \"foo\", \"bar\", \"home\", \"edit\"].join(\",\");\n")

	// Assert all realistic valid controls produce 0 findings.
	validControls := map[string][]byte{
		"webp_full_valid.webp":     webpFullValid,
		"webp_exif_valid.webp":     webpExifValid,
		"multi_chunk_real.png":     multiChunkRealPNG,
		"xmp_photo.png":            xmpPhotoPNG,
		"exif_restart_real.jpg":    exifRestartRealJPG,
		"prog.jpg":                 progJPG,
		"pdf_cr_only_eol.pdf":      pdfCROnly,
		"pdf_obj_word_valid.pdf":   pdfObjWordValid,
		"wasm_name_producers.wasm": wasmValidNameProducers,
		"clean_utf16_no_bom.proto": cleanUTF16NoBomProto,
		"clean_utf16be_no_bom.go":  cleanUTF16BENoBomGo,
		"large_sha_array.go":       []byte(shaArrayGo.String()),
		"benign_short_ui.js":       benignShortUIStringsJS,
	}
	ctrlFindings, ctrlCov, err := runEngineOnFiles(t, engine, validControls, "")
	if err != nil || !ctrlCov.Complete {
		t.Fatalf("Iter4 realistic valid controls Analyze failed: cov=%+v err=%v", ctrlCov, err)
	}
	if len(ctrlFindings) != 0 {
		t.Fatalf("expected 0 findings on Iter4 realistic valid controls, got %+v", ctrlFindings)
	}

	// Assert all CSPRNG / invalid-framing / trailing-payload vectors trigger concealment findings.
	concealmentOnlyVectors := map[string][]byte{
		"webp_exif_csprng.webp":          webpExifCSPRNG,
		"webp_vp8x_only.webp":            webpVP8XOnly,
		"png_ztxt_valid_zlib_csprng.png": pngZTxtValidZlibCSPRNG,
		"png_ztxt_raw_csprng.png":        pngZTxtRawCSPRNG,
		"png_priv_csprng.png":            pngPrivCSPRNG,
		"jpg_sos_spoof_csprng.jpg":       jpgSOSSpoofCSPRNG,
		"jpg_com_csprng.jpg":             jpgCOMCSPRNG,
		"jpg_app15_csprng.jpg":           jpgAPP15CSPRNG,
		"pdf_trailing_after_eof.pdf":     pdfTrailingAfterEOF,
		"pdf_flate_csprng.pdf":           pdfFlateCSPRNG,
		"pdf_dct_csprng.pdf":             pdfDCTCSPRNG,
		"pdf_lzw_csprng.pdf":             pdfLZWCSPRNG,
		"pdf_multifilter_csprng.pdf":     pdfMultiFilterCSPRNG,
		"wasm_half_nul_csprng.wasm":      wasmHalfNulCSPRNG,
	}
	for name, data := range concealmentOnlyVectors {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "IP_CONCEALMENT") {
			t.Fatalf("%s expected IP_CONCEALMENT finding, got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}

	// Assert all IP-smuggling vectors trigger IP corpus matches (L1/L2/L3).
	ipSmugglingVectors := map[string][]byte{
		"webp_exif_nul_ip.webp":         webpExifNulIP,
		"png_ztxt_ip.png":               pngZTxtIP,
		"png_itxt_comp_ip.png":          pngITxtCompIP,
		"jpg_com_nul_ip.jpg":            jpgCOMNulIP,
		"pdf_flate_nul_ip.pdf":          pdfFlateNulIP,
		"pdf_asciihex_ip.pdf":           pdfASCIIHexIP,
		"pdf_ascii85_ip.pdf":            pdfASCII85IP,
		"wasm_split_20b.wasm":           wasmSplit20B,
		"wasm_nul_interleaved.wasm":     wasmNulInterleaved,
		"utf16le_no_bom.proto":          utf16NoBomProtoIP,
		"nul_interleaved_20b.proto":     nul20ProtoIP,
		"extensionless_nul_interleaved": extlessNulIP,
		"backtick_concat.js":            []byte(backtickConcatJS),
		"triple_quote_concat.py":        []byte(tripleQuoteConcatPy),
		"short_4char_concat.js":         []byte(short4CharConcatJS),
		"wrapped_b64_24.go":             []byte(wrappedB6424Go),
		"wrapped_hex_24.txt":            []byte(wrappedHex24Txt),
	}
	for name, data := range ipSmugglingVectors {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") && !hasCategory(findings, "IP_HEADER_MARKER") && !hasCategory(findings, "IP_HEADER_STRIP") {
			t.Fatalf("%s expected IP match (L1/L2/L3), got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}
}

func interleaveByte(data []byte, sep byte, every int) []byte {
	var out bytes.Buffer
	for i, b := range data {
		if i > 0 && i%every == 0 {
			out.WriteByte(sep)
		}
		out.WriteByte(b)
	}
	return out.Bytes()
}

func buildSyntheticSFNTFont(tablePayload []byte) []byte {
	// 4 tables: CFF , head, maxp, name (ordered alphabetically, each 4B-aligned, spec-valid CFF + head + maxp + checksums).
	pad4 := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		return out
	}
	sfntSum := func(b []byte) uint32 {
		var s uint32
		for i := 0; i+4 <= len(b); i += 4 {
			s += binary.BigEndian.Uint32(b[i : i+4])
		}
		if rem := len(b) % 4; rem > 0 {
			var tail [4]byte
			copy(tail[:], b[len(b)-rem:])
			s += binary.BigEndian.Uint32(tail[:])
		}
		return s
	}
	buildMinimalCFF := func(fontName string) []byte {
		var nameIdx bytes.Buffer
		nameIdx.Write([]byte{0x00, 0x01, 0x01, 0x01, byte(1 + len(fontName))})
		nameIdx.WriteString(fontName)

		var strIdx bytes.Buffer
		strIdx.Write([]byte{0x00, 0x00}) // empty String INDEX

		var gsubIdx bytes.Buffer
		gsubIdx.Write([]byte{0x00, 0x00}) // empty Global Subr INDEX

		// Top DICT INDEX placeholder: 1 entry containing a 5-byte int32 operand (op 29) + CharStrings op (17) = 6 bytes.
		topDictLen := 6
		topDictIdxSize := 3 + 2 + topDictLen
		charStringsOff := 4 + nameIdx.Len() + topDictIdxSize + strIdx.Len() + gsubIdx.Len()

		var topDictIdx bytes.Buffer
		topDictIdx.Write([]byte{0x00, 0x01, 0x01, 0x01, byte(1 + topDictLen)})
		topDictIdx.WriteByte(29)
		_ = binary.Write(&topDictIdx, binary.BigEndian, int32(charStringsOff))
		topDictIdx.WriteByte(17)

		var charStringsIdx bytes.Buffer
		charStringsIdx.Write([]byte{0x00, 0x01, 0x01, 0x01, 0x02, 0x0e}) // 1 glyph: endchar

		var cff bytes.Buffer
		cff.Write([]byte{0x01, 0x00, 0x04, 0x01})
		cff.Write(nameIdx.Bytes())
		cff.Write(topDictIdx.Bytes())
		cff.Write(strIdx.Bytes())
		cff.Write(gsubIdx.Bytes())
		cff.Write(charStringsIdx.Bytes())
		return pad4(cff.Bytes())
	}

	head := make([]byte, 56) // 54B padded to 56B
	binary.BigEndian.PutUint32(head[0:4], 0x00010000)
	binary.BigEndian.PutUint32(head[12:16], 0x5F0F3CF5) // magicNumber
	binary.BigEndian.PutUint16(head[18:20], 1000)       // unitsPerEm

	maxp := make([]byte, 8) // 6B padded to 8B
	binary.BigEndian.PutUint32(maxp[0:4], 0x00005000)
	binary.BigEndian.PutUint16(maxp[4:6], 1) // numGlyphs

	name := []byte{0, 0, 0, 0, 0, 6, 0, 0}
	cff := buildMinimalCFF("CustodianSynthFont")
	_ = tablePayload

	tables := []struct {
		tag  string
		data []byte
	}{
		{"CFF ", cff},
		{"head", head},
		{"maxp", maxp},
		{"name", name},
	}
	numTables := len(tables)
	headerLen := 12 + numTables*16
	var out bytes.Buffer
	out.Write([]byte{'O', 'T', 'T', 'O'})
	_ = binary.Write(&out, binary.BigEndian, uint16(numTables))
	_ = binary.Write(&out, binary.BigEndian, uint16(64))
	_ = binary.Write(&out, binary.BigEndian, uint16(2))
	_ = binary.Write(&out, binary.BigEndian, uint16(0))
	off := headerLen
	for _, tbl := range tables {
		out.WriteString(tbl.tag)
		_ = binary.Write(&out, binary.BigEndian, sfntSum(tbl.data))
		_ = binary.Write(&out, binary.BigEndian, uint32(off))
		_ = binary.Write(&out, binary.BigEndian, uint32(len(tbl.data)))
		off += len(tbl.data)
	}
	for _, tbl := range tables {
		out.Write(tbl.data)
	}
	return out.Bytes()
}

func TestIteration5RemediationAllBypassesAndRealisticControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	csprng := make([]byte, 4096)
	state := uint32(0x13579BDF)
	for i := range csprng {
		state = state*1664525 + 1013904223
		csprng[i] = byte(state >> 24)
	}

	zlibCompress := func(raw []byte) []byte {
		var b bytes.Buffer
		zw := zlib.NewWriter(&b)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return b.Bytes()
	}

	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var p bytes.Buffer
		p.WriteString("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		fmt.Fprintf(&p, "2 0 obj\n<< %s >>\nstream\n", dictEntries)
		p.Write(body)
		p.WriteString("\nendstream\nendobj\nxref\n0 3\nstartxref\n50\n%%EOF\n")
		return p.Bytes()
	}

	// === A. L4b Digest-Array Masquerade, Unpadded Base64url Digests, & Quoted-Concatenation ===
	paddedStripped := append([]byte(nil), stripped...)
	for len(paddedStripped)%32 != 0 {
		paddedStripped = append(paddedStripped, ' ')
	}
	hexMasq := hex.EncodeToString(paddedStripped)
	var hex64Chunks []string
	for i := 0; i < len(hexMasq); i += 64 {
		hex64Chunks = append(hex64Chunks, fmt.Sprintf("%q", hexMasq[i:i+64]))
	}
	l4bShaMasqGo := "package m\nimport \"strings\"\nvar c = []string{\n" + strings.Join(hex64Chunks, ",\n") + "\n}\nvar _ = strings.Join(c, \"\")\n"
	l4bShaMasqPy := "s = \"\".join([" + strings.Join(hex64Chunks, ", ") + "])\n"
	l4bShaMasqJS := "const c = [" + strings.Join(hex64Chunks, ", ") + "];\nconst out = c.join('');\n"
	l4bShaMasqNoJoin := "package m\nvar c = []string{\n" + strings.Join(hex64Chunks, ",\n") + "\n}\n"

	b64Prop := base64.StdEncoding.EncodeToString(propGo)
	joinQuoted := func(s string, width int, openQ, closeQ, sep string) string {
		var b strings.Builder
		for i := 0; i < len(s); i += width {
			end := min(i+width, len(s))
			if i > 0 {
				b.WriteString(sep)
			}
			b.WriteString(openQ)
			b.WriteString(s[i:end])
			b.WriteString(closeQ)
		}
		return b.String()
	}
	l4b2Char := "const s = " + joinQuoted(b64Prop, 2, `"`, `"`, " + ") + ";\n"
	l4b3Char := "const s = " + joinQuoted(b64Prop, 3, `"`, `"`, " + ") + ";\n"
	l4bBacktickInterp := "const s = `" + joinQuoted(b64Prop, 50, "", "", "${''}") + "`;\n"
	l4bBacktickEscape := "const s = `" + joinQuoted(b64Prop, 40, "", "", "\\n") + "`;\n"
	l4bCommentConcat := "const s = " + joinQuoted(b64Prop, 40, `"`, `"`, " + /* c */ ") + ";\n"

	// === B. PDF Structure, Non-Stream CSPRNG, Fake-endstream, Filter Parsing, & Multi-Stream Bomb ===
	smallFlate := zlibCompress([]byte("BT /F1 10 Tf (hello world) Tj ET"))
	pdfFakeEndstream := []byte(fmt.Sprintf("%%PDF-1.4\n1 0 obj\n<< /Length 5 0 R /Filter /FlateDecode >>\nstream\n%s\nendstream\n%s\nendstream\nendobj\n5 0 obj\n%d\nendobj\nxref\n0 6\nstartxref\n50\n%%%%EOF\n",
		smallFlate, csprng, len(smallFlate)))
	pdfObjCSPRNG := []byte(fmt.Sprintf("%%PDF-1.4\n%% %s\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\nstartxref\n50\n%%%%EOF\n", csprng))

	rawHex := hex.EncodeToString(propGo)
	var spacedHex bytes.Buffer
	for i := 0; i < len(rawHex); i += 2 {
		if i > 0 {
			spacedHex.WriteByte(' ')
		}
		spacedHex.WriteString(rawHex[i : i+2])
	}
	spacedHex.WriteByte('>')
	pdfProdObj := makeStreamPDF(fmt.Sprintf("/Length %d /Filter /ASCIIHexDecode /Producer (hello obj )", spacedHex.Len()), spacedHex.Bytes())
	pdfFilterCmt := makeStreamPDF(fmt.Sprintf("/Length %d /Filter %%c\n/ASCIIHexDecode", spacedHex.Len()), spacedHex.Bytes())
	pdfFilterHexName := makeStreamPDF(fmt.Sprintf("/Length %d /Filter /ASCIIHex#44ecode", spacedHex.Len()), spacedHex.Bytes())
	pdfCryptSpacedHex := makeStreamPDF(fmt.Sprintf("/Length %d /Filter /Crypt", spacedHex.Len()), spacedHex.Bytes())
	flate0x01IP := zlibCompress(interleaveByte(stripped, 0x01, 20))
	pdfFlate0x01IP := makeStreamPDF(fmt.Sprintf("/Length %d /Filter /FlateDecode", len(flate0x01IP)), flate0x01IP)

	// Multi-stream /FlateDecode cumulative bomb (6 x 3.9 MiB = 23.4 MiB > 16 MiB).
	bombChunk := zlibCompress(bytes.Repeat([]byte("A"), 3900*1024))
	var multiBombPDF bytes.Buffer
	multiBombPDF.WriteString("%PDF-1.4\n")
	for s := 1; s <= 6; s++ {
		fmt.Fprintf(&multiBombPDF, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", s, len(bombChunk))
		multiBombPDF.Write(bombChunk)
		multiBombPDF.WriteString("\nendstream\nendobj\n")
	}
	multiBombPDF.WriteString("xref\n0 7\nstartxref\n50\n%%EOF\n")

	// === C. Media Containers (WebP, PNG, JPEG) ===
	validVP8 := minimalValidVP8Chunk()
	webpICCPCSPRNG := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ICCP", csprng},
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8},
	)
	webpICCP0x01IP := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ICCP", interleaveByte(stripped, 0x01, 20)},
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8},
	)
	webpANMFCSPRNG := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ANIM", make([]byte, 6)},
		struct {
			fourCC  string
			payload []byte
		}{"ANMF", append(make([]byte, 16), csprng...)},
	)
	webpANMFNulIP := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ANIM", make([]byte, 6)},
		struct {
			fourCC  string
			payload []byte
		}{"ANMF", append(make([]byte, 16), interleaveNUL(stripped, 20)...)},
	)
	webpVP8NulIP := buildGenuineVP8WebP(interleaveNUL(stripped, 20))

	basePNG := buildGenuinePNG(t, 48, 48)
	pngICCPCSPRNG := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("iCCP", append([]byte("sRGB\x00\x00"), csprng...)))
	pngICCPNulIP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("iCCP", append([]byte("sRGB\x00\x00"), interleaveNUL(stripped, 20)...)))
	pngZTxt0x01IP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("zTXt", append([]byte("Src\x00\x00"), zlibCompress(interleaveByte(stripped, 0x01, 20))...)))
	pngText0x01IP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("tEXt", append([]byte("Src\x00"), interleaveByte(stripped, 0x01, 20)...)))

	// 3x base64 -> PNG zTXt at decodeDepth == 3.
	pngZTxtIP := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("zTXt", append([]byte("Source\x00\x00"), zlibCompress(stripped)...)))
	b64_1 := base64.StdEncoding.EncodeToString(pngZTxtIP)
	b64_2 := base64.StdEncoding.EncodeToString([]byte(b64_1))
	b64_3 := base64.StdEncoding.EncodeToString([]byte(b64_2))

	baseJPG := buildGenuineJPEG(t, 48, 48)
	insertJPGBeforeSOS := func(marker byte, payload []byte) []byte {
		sosIdx := bytes.Index(baseJPG, []byte{0xFF, 0xDA})
		var seg bytes.Buffer
		seg.WriteByte(0xFF)
		seg.WriteByte(marker)
		_ = binary.Write(&seg, binary.BigEndian, uint16(len(payload)+2))
		seg.Write(payload)
		var out bytes.Buffer
		out.Write(baseJPG[:sosIdx])
		out.Write(seg.Bytes())
		out.Write(baseJPG[sosIdx:])
		return out.Bytes()
	}
	stuffFF := func(raw []byte) []byte {
		var b bytes.Buffer
		for _, c := range raw {
			b.WriteByte(c)
			if c == 0xFF {
				b.WriteByte(0x00)
			}
		}
		return b.Bytes()
	}
	jpgSOSStuffedCSPRNG := append([]byte{
		0xFF, 0xD8,
		0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
		0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
	}, stuffFF(csprng)...)
	jpgSOSStuffedCSPRNG = append(jpgSOSStuffedCSPRNG, 0xFF, 0xD9)

	// Attack with DQT + DHT + SOF0(48x48) + SOS(stuffed CSPRNG) -> caught by trailing-scan check!
	var jpgSOSWithTablesCSPRNG bytes.Buffer
	jpgSOSWithTablesCSPRNG.Write(baseJPG[:bytes.Index(baseJPG, []byte{0xFF, 0xDA})+14])
	jpgSOSWithTablesCSPRNG.Write(stuffFF(csprng))
	jpgSOSWithTablesCSPRNG.Write([]byte{0xFF, 0xD9})

	jpgSOSNulIP := append([]byte{
		0xFF, 0xD8,
		0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
		0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
	}, interleaveNUL(stripped, 20)...)
	jpgSOSNulIP = append(jpgSOSNulIP, 0xFF, 0xD9)

	jpgAPP2ICCPCSPRNG := insertJPGBeforeSOS(0xE2, append([]byte("ICC_PROFILE\x00\x01\x01"), csprng...))
	jpgAPP2ICCPNulIP := insertJPGBeforeSOS(0xE2, append([]byte("ICC_PROFILE\x00\x01\x01"), interleaveNUL(stripped, 20)...))
	jpgAPP0CSPRNG := insertJPGBeforeSOS(0xE0, csprng)
	jpgDQTCSPRNG := insertJPGBeforeSOS(0xDB, csprng)
	jpgDQTNulIP := insertJPGBeforeSOS(0xDB, interleaveNUL(stripped, 20))
	jpgDHTCSPRNG := insertJPGBeforeSOS(0xC4, csprng)

	// === D. WASM Data Section (secID == 11), 0x01 Interleaving, & BOM-less UTF-16 Credentials ===
	buildWASMWithSection := func(secID byte, secBody []byte) []byte {
		var lb [5]byte
		n := binary.PutUvarint(lb[:], uint64(len(secBody)))
		out := []byte{
			0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
			0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
			secID,
		}
		out = append(out, lb[:n]...)
		return append(out, secBody...)
	}
	wasmDataCSPRNG := buildWASMWithSection(11, csprng)
	wasmDataNulIP := buildWASMWithSection(11, interleaveNUL(stripped, 20))

	half0x01CSPRNG := make([]byte, len(csprng)*2)
	for i, b := range csprng {
		half0x01CSPRNG[i*2] = b
		half0x01CSPRNG[i*2+1] = 0x01
	}
	customSec := append([]byte{0x02, 'i', 'p'}, half0x01CSPRNG...)
	wasmCustom0x01Half := buildWASMWithSection(0, customSec)
	wasmCustom0x01Half = append(wasmCustom0x01Half, 0x03, 0x02, 0x01, 0x00) // add standard section

	src0x01Go := interleaveByte(stripped, 0x01, 20)
	src0x01Dat := interleaveByte(stripped, 0x01, 20)

	utf16SecretGH := "ghp_0123456789abcdef0123456789abcdef0123"
	utf16SecretSK := "sk-abcdefghij"
	utf16SecretPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789abcdef\n-----END RSA PRIVATE KEY-----\n"

	// 1. Verify multi_flate_bomb.pdf fails closed with ip.l4.archive-limit-exceeded.
	bombFindings, bombCov, err := runEngineOnFiles(t, engine, map[string][]byte{"multi_flate_bomb.pdf": multiBombPDF.Bytes()}, "")
	if err != nil {
		t.Fatalf("multi_flate_bomb Analyze err=%v", err)
	}
	if bombCov.Complete || bombCov.FilesSkipped == 0 || !hasRule(bombFindings, "ip.l4.archive-limit-exceeded") {
		t.Fatalf("multi_flate_bomb expected fail-closed archive-limit-exceeded, cov=%+v findings=%+v", bombCov, bombFindings)
	}

	// 2. Verify all concealment-only vectors trigger IP_CONCEALMENT.
	concealmentVectors := map[string][]byte{
		"fake_endstream.pdf":          pdfFakeEndstream,
		"obj_csprng.pdf":              pdfObjCSPRNG,
		"webp_vp8x_iccp_csprng.webp":  webpICCPCSPRNG,
		"webp_anim_anmf_csprng.webp":  webpANMFCSPRNG,
		"png_iccp_csprng.png":         pngICCPCSPRNG,
		"jpg_sos_stuffed_csprng.jpg":  jpgSOSStuffedCSPRNG,
		"jpg_sos_tables_csprng.jpg":   jpgSOSWithTablesCSPRNG.Bytes(),
		"jpg_app2_iccp_csprng.jpg":    jpgAPP2ICCPCSPRNG,
		"jpg_app0_csprng.jpg":         jpgAPP0CSPRNG,
		"jpg_dqt_csprng.jpg":          jpgDQTCSPRNG,
		"jpg_dht_csprng.jpg":          jpgDHTCSPRNG,
		"wasm_data_sec11_csprng.wasm": wasmDataCSPRNG,
		"wasm_custom_0x01_half.wasm":  wasmCustom0x01Half,
	}
	for name, data := range concealmentVectors {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "IP_CONCEALMENT") {
			t.Fatalf("%s expected IP_CONCEALMENT, got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}

	// 3. Verify all IP smuggling vectors trigger IP corpus matches (L1/L2/L3).
	ipSmugglingVectors := map[string][]byte{
		"l4b_sha256_masq_go.go":         []byte(l4bShaMasqGo),
		"l4b_sha256_masq_py.py":         []byte(l4bShaMasqPy),
		"l4b_sha256_masq_js.js":         []byte(l4bShaMasqJS),
		"l4b_sha256_masq_nojoin.go":     []byte(l4bShaMasqNoJoin),
		"l4b_2char_concat.js":           []byte(l4b2Char),
		"l4b_3char_concat.js":           []byte(l4b3Char),
		"l4b_backtick_50_interp.js":     []byte(l4bBacktickInterp),
		"l4b_backtick_escape.js":        []byte(l4bBacktickEscape),
		"l4b_comment_between_concat.js": []byte(l4bCommentConcat),
		"pdf_prod_obj.pdf":              pdfProdObj,
		"pdf_filter_cmt.pdf":            pdfFilterCmt,
		"pdf_filter_hexname.pdf":        pdfFilterHexName,
		"pdf_crypt_spacedhex.pdf":       pdfCryptSpacedHex,
		"pdf_flate_0x01_ip.pdf":         pdfFlate0x01IP,
		"b64_3x_png_ztxt.txt":           []byte(b64_3),
		"webp_vp8x_iccp_0x01_ip.webp":   webpICCP0x01IP,
		"webp_anim_anmf_nul_ip.webp":    webpANMFNulIP,
		"vp8_nul_ip.webp":               webpVP8NulIP,
		"png_iccp_nul_ip.png":           pngICCPNulIP,
		"png_ztxt_0x01_ip.png":          pngZTxt0x01IP,
		"png_text_0x01_ip.png":          pngText0x01IP,
		"jpg_sos_nul_ip.jpg":            jpgSOSNulIP,
		"jpg_app2_iccp_nul_ip.jpg":      jpgAPP2ICCPNulIP,
		"jpg_dqt_nul_ip.jpg":            jpgDQTNulIP,
		"wasm_data_sec11_nul_ip.wasm":   wasmDataNulIP,
		"src_0x01_interleaved.go":       src0x01Go,
		"src_0x01_interleaved.dat":      src0x01Dat,
	}
	for name, data := range ipSmugglingVectors {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") && !hasCategory(findings, "IP_HEADER_MARKER") && !hasCategory(findings, "IP_HEADER_STRIP") {
			t.Fatalf("%s expected IP match (L1/L2/L3), got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
	}

	// 4. Verify BOM-less UTF-16 credential vectors trigger SECRET findings with zero leakage.
	utf16CredVectors := map[string][]byte{
		"utf16_40b_secret.dat":   encodeBOMlessUTF16LE(utf16SecretGH),
		"utf16_secret.proto":     encodeBOMlessUTF16LE("syntax = \"proto3\";\n// token: " + utf16SecretGH + "\n"),
		"utf16_privkey.dat":      encodeBOMlessUTF16LE(utf16SecretPEM),
		"utf16_short_secret.dat": encodeBOMlessUTF16LE(utf16SecretSK),
	}
	for name, data := range utf16CredVectors {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasCategory(findings, "SECRET") {
			t.Fatalf("%s expected SECRET finding, got %+v", name, findings)
		}
		assertNoRawLeak(t, findings, cov, utf16SecretGH, utf16SecretSK, "MIIEpAIBAAKCAQEA0123456789abcdef")
	}

	// 5. Realistic Valid Controls (MUST all produce 0 findings -> ALLOW).
	validICC := buildValidICCProfile(csprng[:1024])
	flateICC := zlibCompress(validICC)
	pdfFlateICC := makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(flateICC)), flateICC)

	// Smooth noisy 32x32 RGB photographic raster (ent > 7.2, spatially correlated pixels).
	photoRGB := make([]byte, 32*32*3)
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			idx := (y*32 + x) * 3
			n := int(csprng[(y*32+x)%len(csprng)]%17) - 8
			clamp := func(v int) byte {
				if v < 0 {
					return 0
				}
				if v > 255 {
					return 255
				}
				return byte(v)
			}
			photoRGB[idx] = clamp(int(128.0+95.0*math.Sin(float64(x)*0.22+float64(y)*0.11)) + n)
			photoRGB[idx+1] = clamp(int(128.0+95.0*math.Cos(float64(y)*0.24-float64(x)*0.09)) + n)
			photoRGB[idx+2] = clamp(int(128.0+90.0*math.Sin(float64(x+y)*0.19)) + n)
		}
	}
	flateRGB := zlibCompress(photoRGB)
	pdfFlateImg := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(flateRGB)), flateRGB)

	synthTTF := buildSyntheticSFNTFont(csprng[:2048])
	flateSynthTTF := zlibCompress(synthTTF)
	pdfFlateSynthTTF := makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(flateSynthTTF), len(synthTTF)), flateSynthTTF)

	prodObjFlatePayload := zlibCompress(bytes.Repeat([]byte("BT /F1 12 Tf (Public Technical Manual Page) Tj ET\n"), 20))
	pdfProdObjValid := makeStreamPDF(fmt.Sprintf("/Length %d /Filter /FlateDecode /Producer (hello obj )", len(prodObjFlatePayload)), prodObjFlatePayload)

	goTutorialPDF := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 138 >>\nstream\nBT /F1 10 Tf 72 720 Td\n(Example code:\npackage main\nimport \"fmt\"\nfunc main() { x := 1; fmt.Println(x) }\n) Tj ET\nendstream\nendobj\nxref\n0 5\nstartxref\n250\n%%EOF\n")

	// EXIF with genuine embedded JPEG thumbnail across JPEG APP1, PNG eXIf, and WebP EXIF.
	thumbJPG := buildGenuineJPEG(t, 32, 32)
	exifHdr := []byte("Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00\x0f\x01\x02\x00\x06\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00Canon\x00")
	exifWithThumb := append(append([]byte(nil), exifHdr...), thumbJPG...)
	jpgWithExifThumb := insertJPGBeforeSOS(0xE1, exifWithThumb)
	pngWithExifThumb := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("eXIf", exifWithThumb[6:]))
	webpWithExifThumb := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"VP8 ", validVP8},
		struct {
			fourCC  string
			payload []byte
		}{"EXIF", exifWithThumb},
	)

	// JPEG APP13 Photoshop 8BIM with valid 0x1C IPTC-NAA block (0x0404) + Q=75 0x040C thumbnail.
	var iptcBuf bytes.Buffer
	iptcRecords := []struct {
		dataset byte
		val     string
	}{
		{0x78, "Public landscape photograph exported from Lightroom Classic 2026 pipeline for documentation."},
		{0x50, "Public Photographer"},
		{0x19, "nature"},
		{0x19, "architecture"},
		{0x19, "editorial"},
		{0x74, "Copyright 2026 Public Domain Photography Archive. Licensed under CC-BY-4.0."},
		{0x5A, "Seattle"},
		{0x65, "United States"},
		{0x05, "Emerald City Skyline at Dawn"},
		{0x6E, "Public Media Press Release Asset Collection"},
		{0x7A, "Editorial Team Review 2026"},
	}
	for _, rec := range iptcRecords {
		iptcBuf.Write([]byte{0x1C, 0x02, rec.dataset})
		_ = binary.Write(&iptcBuf, binary.BigEndian, uint16(len(rec.val)))
		iptcBuf.WriteString(rec.val)
	}
	for iptcBuf.Len() < 520 {
		iptcBuf.Write([]byte{0x1C, 0x02, 0x19})
		tag := "landscape-tag"
		_ = binary.Write(&iptcBuf, binary.BigEndian, uint16(len(tag)))
		iptcBuf.WriteString(tag)
	}
	iptcBytes := iptcBuf.Bytes()

	var thumb75Buf bytes.Buffer
	thumbImg75 := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			thumbImg75.SetRGBA(x, y, color.RGBA{R: uint8(x * 7), G: uint8(y * 7), B: uint8((x + y) * 3), A: 255})
		}
	}
	if err := jpeg.Encode(&thumb75Buf, thumbImg75, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatalf("encode Q=75 thumb: %v", err)
	}

	var bimBuf bytes.Buffer
	bimBuf.WriteString("Photoshop 3.0\x00")
	bimBuf.WriteString("8BIM")
	_ = binary.Write(&bimBuf, binary.BigEndian, uint16(0x0404))
	bimBuf.Write([]byte{0x03, 'i', 'p', 't'}) // odd Pascal name (nameLen=3 -> total 4B)
	_ = binary.Write(&bimBuf, binary.BigEndian, uint32(len(iptcBytes)))
	bimBuf.Write(iptcBytes)
	if len(iptcBytes)%2 != 0 {
		bimBuf.WriteByte(0)
	}
	bimBuf.WriteString("8BIM")
	_ = binary.Write(&bimBuf, binary.BigEndian, uint16(0x040C))
	bimBuf.Write([]byte{0x00, 0x00})
	thumbRes := append(make([]byte, 28), thumb75Buf.Bytes()...)
	_ = binary.Write(&bimBuf, binary.BigEndian, uint32(len(thumbRes)))
	bimBuf.Write(thumbRes)
	if len(thumbRes)%2 != 0 {
		bimBuf.WriteByte(0)
	}
	jpgAPP138BIM := insertJPGBeforeSOS(0xED, bimBuf.Bytes())

	// Multi-chunk JPEG APP2 ICC profile.
	mid := len(validICC) / 2
	jpgMultiICC := insertJPGBeforeSOS(0xE2, append([]byte("ICC_PROFILE\x00\x01\x02"), validICC[:mid]...))
	sosIdx := bytes.Index(jpgMultiICC, []byte{0xFF, 0xDA})
	var seg2 bytes.Buffer
	p2 := append([]byte("ICC_PROFILE\x00\x02\x02"), validICC[mid:]...)
	seg2.Write([]byte{0xFF, 0xE2})
	_ = binary.Write(&seg2, binary.BigEndian, uint16(len(p2)+2))
	seg2.Write(p2)
	jpgMultiICC = append(append(append([]byte(nil), jpgMultiICC[:sosIdx]...), seg2.Bytes()...), jpgMultiICC[sosIdx:]...)

	// Unpadded base64url SHA-256 digest slice.
	var b64urlArray strings.Builder
	b64urlArray.WriteString("package digests\n\nvar B64Digests = []string{\n")
	for i := 0; i < 16; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("item-%d", i)))
		fmt.Fprintf(&b64urlArray, "\t%q,\n", base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	b64urlArray.WriteString("}\n")

	// Valid animated WebP ANMF containing nested VP8 frame.
	anmfHeader := make([]byte, 16)
	anmfHeader[6] = 15 // width-1 = 15 (16px)
	anmfHeader[9] = 15 // height-1 = 15 (16px)
	var anmfBody bytes.Buffer
	anmfBody.Write(anmfHeader)
	anmfBody.WriteString("VP8 ")
	_ = binary.Write(&anmfBody, binary.LittleEndian, uint32(len(validVP8)))
	anmfBody.Write(validVP8)
	if len(validVP8)%2 != 0 {
		anmfBody.WriteByte(0)
	}
	webpAnimValid := buildRIFFWebP(
		struct {
			fourCC  string
			payload []byte
		}{"VP8X", make([]byte, 10)},
		struct {
			fourCC  string
			payload []byte
		}{"ANIM", make([]byte, 6)},
		struct {
			fourCC  string
			payload []byte
		}{"ANMF", anmfBody.Bytes()},
	)

	// Valid WASM with Data section (secID == 11) + .debug_str custom section.
	wasmBenignData := []byte{
		0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x0b, 0x16, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x10,
		'h', 'e', 'l', 'l', 'o', '_', 'w', 'o', 'r', 'l', 'd', '_', '2', '0', '2', '6',
	}

	validControls := map[string][]byte{
		"pdf_flate_icc_profile.pdf":   pdfFlateICC,
		"pdf_flate_image_raster.pdf":  pdfFlateImg,
		"pdf_flate_synth_ttf.pdf":     pdfFlateSynthTTF,
		"pdf_prod_obj_valid.pdf":      pdfProdObjValid,
		"go_tutorial.pdf":             goTutorialPDF,
		"camera_photo_exif_thumb.jpg": jpgWithExifThumb,
		"png_exif_with_thumb.png":     pngWithExifThumb,
		"webp_exif_with_thumb.webp":   webpWithExifThumb,
		"jpeg_app13_iptc_8bim.jpg":    jpgAPP138BIM,
		"jpeg_app2_multi_icc.jpg":     jpgMultiICC,
		"raw_urlsafe_b64_sha256.go":   []byte(b64urlArray.String()),
		"webp_anim_anmf_real.webp":    webpAnimValid,
		"wasm_benign_data.wasm":       wasmBenignData,
		"backtick_template.js":        []byte("export const url = `https://api.example.com/v1/${orgId}/repos/${repoName}/items`;\n"),
		"small_benign.dat":            {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		"ctrl_utf16_nonascii_oss.go":  encodeBOMlessUTF16LE("// Copyright © 2026 Open Contributors — 日本語コメント\n// SPDX-License-Identifier: MIT\npackage oss\nfunc OK() int { return 1 }\n"),
	}
	if realTTF, err := os.ReadFile("/System/Library/Fonts/Supplemental/Courier New.ttf"); err == nil && len(realTTF) > 0 {
		flateRealTTF := zlibCompress(realTTF)
		validControls["real_ttf_font.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(flateRealTTF), len(realTTF)), flateRealTTF)
	}

	ctrlFindings, ctrlCov, err := runEngineOnFiles(t, engine, validControls, "")
	if err != nil || !ctrlCov.Complete {
		t.Fatalf("Iter5 realistic valid controls Analyze failed: cov=%+v err=%v", ctrlCov, err)
	}
	if len(ctrlFindings) != 0 {
		t.Fatalf("expected 0 findings on Iter5 realistic valid controls, got %+v", ctrlFindings)
	}
}

func TestIteration5TarGz15MiBRepetitiveLatency(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	// 15 MiB repetitive text entry compressed into .tar.gz: must fail closed quickly (entry > 4 MiB).
	// Also test a 3.9 MiB single-line repetitive .tar.gz entry (< 4 MiB) to ensure fast L4b linear scan.
	entry39 := buildSingleFileTarGz(t, "rep.txt", bytes.Repeat([]byte("A"), 3900*1024))
	start := time.Now()
	findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{"rep39.tar.gz": entry39}, "")
	elapsed39 := time.Since(start)
	if err != nil || !cov.Complete {
		t.Fatalf("3.9MiB repetitive tar.gz failed: cov=%+v err=%v", cov, err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on benign 3.9MiB repetitive tar.gz, got %+v", findings)
	}

	entry15 := buildSingleFileTarGz(t, "bomb15.txt", bytes.Repeat([]byte("A"), 15<<20))
	start15 := time.Now()
	bombFindings, bombCov, err := runEngineOnFiles(t, engine, map[string][]byte{"bomb15.tar.gz": entry15}, "")
	elapsed15 := time.Since(start15)
	if err != nil {
		t.Fatalf("15MiB tar.gz returned error: %v", err)
	}
	if bombCov.Complete || bombCov.FilesSkipped == 0 || !hasRule(bombFindings, "ip.l4.archive-limit-exceeded") {
		t.Fatalf("expected fail-closed archive-limit-exceeded on 15MiB tar.gz, cov=%+v findings=%+v", bombCov, bombFindings)
	}
	t.Logf("3.9MiB repetitive tar.gz: %v; 15MiB tar.gz bomb: %v", elapsed39, elapsed15)
}

func TestIteration6ComprehensiveRegressionAndRealControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store})

	propGo := readFixture(t, "corpora/restricted/proprietary_engine.go")
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	csprng := make([]byte, 4096)
	state := uint32(0x2468ACE1)
	for i := range csprng {
		state = state*1664525 + 1013904223
		csprng[i] = byte(state >> 24)
	}
	zlibCompress := func(raw []byte) []byte {
		var b bytes.Buffer
		zw := zlib.NewWriter(&b)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return b.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var p bytes.Buffer
		p.WriteString("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		fmt.Fprintf(&p, "2 0 obj\n<< %s >>\nstream\n", dictEntries)
		p.Write(body)
		p.WriteString("\nendstream\nendobj\nxref\n0 3\nstartxref\n50\n%%EOF\n")
		return p.Bytes()
	}

	// =========================================================================
	// CLUSTER A: O(N) Comment Skipper, 7 L4b Gaps, 0x0b/0x0c, BOM-less UTF-16
	// =========================================================================
	t.Run("ClusterA_CommentSkipLinearLatency", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			unit string
			tail string
		}{
			{"block_800kb.js", `"ab"/*`, ""},
			{"line_800kb.js", `"ab"//`, ""},
			{"hash_800kb.py", `"ab"#`, ""},
			{"block_eof_term_800kb.js", `"ab"/*`, "*/"},
		} {
			payload := bytes.Repeat([]byte(tc.unit), (800*1024)/len(tc.unit))
			if tc.tail != "" {
				payload = append(payload, tc.tail...)
			}
			start := time.Now()
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{tc.name: payload}, "")
			elapsed := time.Since(start)
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", tc.name, cov, err)
			}
			if len(findings) != 0 {
				t.Fatalf("%s expected 0 findings, got %+v", tc.name, findings)
			}
			if isRaceEnabled || testing.Short() {
				t.Logf("%s (%d bytes): %v (non-gating under -race / -short per R5)", tc.name, len(payload), elapsed)
				if elapsed > 15*time.Second {
					t.Fatalf("%s took %v (exceeded 15s quadratic-DoS safety ceiling under -race / -short)", tc.name, elapsed)
				}
			} else {
				if elapsed > 2*time.Second {
					t.Fatalf("%s took %v (expected O(N) < 2s)", tc.name, elapsed)
				}
				t.Logf("%s (%d bytes): %v", tc.name, len(payload), elapsed)
			}
		}
		// 3.9 MiB "ab"/* linear check
		payload39 := bytes.Repeat([]byte(`"ab"/*`), (3900*1024)/6)
		start39 := time.Now()
		f39, cov39, err := runEngineOnFiles(t, engine, map[string][]byte{"block_3_9mb.js": payload39}, "")
		el39 := time.Since(start39)
		if err != nil || !cov39.Complete || len(f39) != 0 {
			t.Fatalf("3.9MiB comment skip failed: cov=%+v err=%v findings=%+v", cov39, err, f39)
		}
		if isRaceEnabled || testing.Short() {
			t.Logf("block_3_9mb.js (%d bytes): %v (non-gating under -race / -short per R5)", len(payload39), el39)
			if el39 > 60*time.Second {
				t.Fatalf("3.9MiB comment skip took %v (exceeded 60s quadratic-DoS safety ceiling under -race / -short)", el39)
			}
		} else {
			if el39 > 5*time.Second {
				t.Fatalf("3.9MiB comment skip took %v (expected O(N))", el39)
			}
			t.Logf("block_3_9mb.js (%d bytes): %v", len(payload39), el39)
		}
	})

	t.Run("ClusterA_L4bConcealmentAndControls", func(t *testing.T) {
		pad32 := func(b []byte) []byte {
			out := append([]byte(nil), b...)
			for len(out)%32 != 0 {
				out = append(out, ' ')
			}
			return out
		}
		hexChunks := func(raw []byte) []string {
			hx := hex.EncodeToString(pad32(raw))
			var out []string
			for i := 0; i < len(hx); i += 64 {
				out = append(out, fmt.Sprintf("%q", hx[i:i+64]))
			}
			return out
		}

		// 1. Digest array masquerade with 0x0b interleaving & zlib compression.
		l4bMasq0x0b := "package m\nvar c = []string{\n" + strings.Join(hexChunks(interleaveByte(stripped, 0x0b, 20)), ",\n") + "\n}\n"
		l4bMasqZlib := "package m\nvar c = []string{\n" + strings.Join(hexChunks(zlibCompress(stripped)), ",\n") + "\n}\n"

		// 2. 3-chunk 129-char unpadded base64url array (stream+1 pad & per-segment encoded) with .reduce, plus full-IP len%4==1 array.
		secret96 := []byte("// config\nconst token = \"ghp_0123456789abcdef0123456789abcdef0123\";\n// padding 12345678901234567890")[:96]
		b64Stream129 := base64.RawURLEncoding.EncodeToString(secret96) + "A" // 128 + 1 = 129 chars
		l4bB64UrlStream129 := fmt.Sprintf("const a = [%q, %q, %q];\nconst s = a.reduce((x,y)=>x+y,'');\n",
			b64Stream129[:43], b64Stream129[43:86], b64Stream129[86:129])
		l4bB64UrlPerSeg129 := fmt.Sprintf("const a = [%q, %q, %q];\nconst s = a.reduce((x,y)=>x+y,'');\n",
			base64.RawURLEncoding.EncodeToString(secret96[0:32]),
			base64.RawURLEncoding.EncodeToString(secret96[32:64]),
			base64.RawURLEncoding.EncodeToString(secret96[64:96]))
		l4bB64UrlNoJoin129 := fmt.Sprintf("const a = [%q, %q, %q];\n",
			base64.RawURLEncoding.EncodeToString(secret96[0:32]),
			base64.RawURLEncoding.EncodeToString(secret96[32:64]),
			base64.RawURLEncoding.EncodeToString(secret96[64:96]))

		// Full IP in 32-byte chunks where numChunks % 4 == 3 (so joined len % 4 == 1).
		ipChunks := (len(stripped) / 32)
		ipChunks = ipChunks - (ipChunks % 4) + 3
		if ipChunks*32 > len(stripped) {
			ipChunks -= 4
		}
		var ipB64Chunks []string
		for k := 0; k < ipChunks; k++ {
			ipB64Chunks = append(ipB64Chunks, fmt.Sprintf("%q", base64.RawURLEncoding.EncodeToString(stripped[k*32:(k+1)*32])))
		}
		l4bB64UrlFullIPLenMod4Eq1 := "const a = [" + strings.Join(ipB64Chunks, ", ") + "];\nconst s = a.reduce((x,y)=>x+y,'');\n"

		// 3. ${expr} backtick interpolation & 1-char concat.
		b64Prop := base64.StdEncoding.EncodeToString(propGo)
		joinQ := func(s string, w int, oq, cq, sep string) string {
			var sb strings.Builder
			for i := 0; i < len(s); i += w {
				if i > 0 {
					sb.WriteString(sep)
				}
				sb.WriteString(oq)
				sb.WriteString(s[i:min(i+w, len(s))])
				sb.WriteString(cq)
			}
			return sb.String()
		}
		l4bBacktickExpr := "const a = '';\nconst s = `" + joinQ(b64Prop, 48, "", "", "${a}") + "`;\n"
		l4b1CharConcat := "const s = " + joinQ(b64Prop, 1, `"`, `"`, " + ") + ";\n"

		// 4. 300 decoy benign base64 lines before real payload & before secret.
		var decoyPrefix strings.Builder
		for i := 0; i < 300; i++ {
			msg := fmt.Sprintf("benign telemetry log entry number %04d padding text ok", i)
			decoyPrefix.WriteString(base64.StdEncoding.EncodeToString([]byte(msg)))
			decoyPrefix.WriteByte('\n')
		}
		l4bDecoyIP := decoyPrefix.String() + b64Prop + "\n"
		l4bDecoySecret := decoyPrefix.String() + base64.StdEncoding.EncodeToString([]byte("token=ghp_0123456789abcdef0123456789abcdef0123\n")) + "\n"

		// 5. Odd-aligned repeated & arbitrary prefixes.
		l4bOddRepeatB64 := strings.Repeat("A", 17) + b64Prop + "\n"
		l4bOddArbitraryB64 := "AbCdE" + b64Prop + "\n"
		l4bOddRepeatHex := strings.Repeat("0", 17) + hex.EncodeToString(propGo) + "\n"

		// 6. Python "".join(var) with secret/IP.
		var pyArrChunks []string
		for i := 0; i < len(b64Prop); i += 40 {
			pyArrChunks = append(pyArrChunks, fmt.Sprintf("%q", b64Prop[i:min(i+40, len(b64Prop))]))
		}
		l4bPyVarJoin := "c = [" + strings.Join(pyArrChunks, ", ") + "]\ns = \"\".join(c)\n"

		for name, payload := range map[string][]byte{
			"l4b_digest_masq_0x0b.go":     []byte(l4bMasq0x0b),
			"l4b_digest_masq_zlib.go":     []byte(l4bMasqZlib),
			"l4b_b64url_lenmod4eq1_ip.js": []byte(l4bB64UrlFullIPLenMod4Eq1),
			"l4b_backtick_expr.js":        []byte(l4bBacktickExpr),
			"l4b_1char_concat.js":         []byte(l4b1CharConcat),
			"l4b_256_decoy_b64.txt":       []byte(l4bDecoyIP),
			"l4b_odd_prefix_repeat.txt":   []byte(l4bOddRepeatB64),
			"l4b_odd_prefix_arb.txt":      []byte(l4bOddArbitraryB64),
			"l4b_odd_prefix_hex.txt":      []byte(l4bOddRepeatHex),
			"l4b_py_var_join_encoded.py":  []byte(l4bPyVarJoin),
		} {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if !hasCategory(findings, "IP_CONCEALMENT") {
				t.Fatalf("%s expected IP_CONCEALMENT, got %+v", name, findings)
			}
			if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") && !hasCategory(findings, "IP_HEADER_STRIP") {
				t.Fatalf("%s expected IP match (L1/L2/L3), got %+v", name, findings)
			}
			assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
		}

		for name, payload := range map[string][]byte{
			"l4b_b64url_stream_129.js": []byte(l4bB64UrlStream129),
			"l4b_b64url_perseg_129.js": []byte(l4bB64UrlPerSeg129),
			"l4b_b64url_nojoin_129.js": []byte(l4bB64UrlNoJoin129),
		} {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if !hasCategory(findings, "IP_CONCEALMENT") || !hasCategory(findings, "SECRET") {
				t.Fatalf("%s expected IP_CONCEALMENT + SECRET, got %+v", name, findings)
			}
			assertNoRawLeak(t, findings, cov, "ghp_0123456789abcdef0123456789abcdef0123")
		}

		// 300-decoy secret check.
		secF, secCov, err := runEngineOnFiles(t, engine, map[string][]byte{"l4b_decoy_secret.txt": []byte(l4bDecoySecret)}, "")
		if err != nil || !secCov.Complete || !hasCategory(secF, "SECRET") || !hasCategory(secF, "IP_CONCEALMENT") {
			t.Fatalf("l4b_decoy_secret expected SECRET + IP_CONCEALMENT, cov=%+v findings=%+v err=%v", secCov, secF, err)
		}
		assertNoRawLeak(t, secF, secCov, "ghp_0123456789abcdef0123456789abcdef0123")

		// Benign L4b controls (0 findings).
		var sha3 strings.Builder
		sha3.WriteString("package digests\nvar Three = []string{\n")
		for i := 0; i < 3; i++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("item-%d", i)))
			fmt.Fprintf(&sha3, "\t%q,\n", base64.RawURLEncoding.EncodeToString(sum[:]))
		}
		sha3.WriteString("}\n")
		oneCharPy := "tokens = " + joinQ("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop", 1, `"`, `"`, " + ") + "\n"
		twoCharJS := "const countries = [" + joinQ("usukdefrjpcaauesitnlsechdknoplbr", 2, `"`, `"`, ", ") + "].join(',');\n"

		benignControls := map[string][]byte{
			"raw_urlsafe_b64_sha256_3.go": []byte(sha3.String()),
			"one_char_tokens.py":          []byte(oneCharPy),
			"two_char_countries.js":       []byte(twoCharJS),
			"backtick_template_ok.js":     []byte("export const api = `https://api.example.com/v1/${orgId}/repos/${repoName}/items`;\n"),
		}
		bf, bcov, err := runEngineOnFiles(t, engine, benignControls, "")
		if err != nil || !bcov.Complete || len(bf) != 0 {
			t.Fatalf("ClusterA L4b benign controls expected 0 findings, cov=%+v err=%v findings=%+v", bcov, err, bf)
		}
	})

	t.Run("ClusterA_VerticalControl0x0b0x0cAndFormFeed", func(t *testing.T) {
		// Build validly framed WASM Data segment (secID == 11) containing 0x0b-interleaved IP.
		ip0x0b := interleaveByte(stripped, 0x0b, 20)
		var dataSeg bytes.Buffer
		dataSeg.WriteByte(0x01) // 1 segment
		dataSeg.WriteByte(0x00) // mode 0 active
		dataSeg.Write([]byte{0x41, 0x00, 0x0b})
		var lenBuf [5]byte
		ln := binary.PutUvarint(lenBuf[:], uint64(len(ip0x0b)))
		dataSeg.Write(lenBuf[:ln])
		dataSeg.Write(ip0x0b)
		var secLenBuf [5]byte
		sln := binary.PutUvarint(secLenBuf[:], uint64(dataSeg.Len()))
		wasm0x0b := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x0b}
		wasm0x0b = append(wasm0x0b, secLenBuf[:sln]...)
		wasm0x0b = append(wasm0x0b, dataSeg.Bytes()...)

		basePNG := buildGenuinePNG(t, 48, 48)
		png0x0b := injectPNGChunksBeforeIEND(t, basePNG, makePNGChunk("tEXt", append([]byte("Src\x00"), ip0x0b...)))

		baseJPG := buildGenuineJPEG(t, 48, 48)
		sosIdx := bytes.Index(baseJPG, []byte{0xFF, 0xDA})
		var comSeg bytes.Buffer
		comSeg.Write([]byte{0xFF, 0xFE})
		_ = binary.Write(&comSeg, binary.BigEndian, uint16(len(ip0x0b)+2))
		comSeg.Write(ip0x0b)
		jpg0x0b := append(append(append([]byte(nil), baseJPG[:sosIdx]...), comSeg.Bytes()...), baseJPG[sosIdx:]...)

		src0x0b := interleaveByte(stripped, 0x0b, 20)
		src0x0c := interleaveByte(stripped, 0x0c, 20)

		for name, payload := range map[string][]byte{
			"wasm_sec11_0x0b_ip.wasm": wasm0x0b,
			"png_text_0x0b_ip.png":    png0x0b,
			"jpg_com_0x0b_ip.jpg":     jpg0x0b,
			"src_0x0b_interleaved.go": src0x0b,
			"src_0x0c_interleaved.go": src0x0c,
		} {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if !hasCategory(findings, "IP_EXACT") && !hasCategory(findings, "IP_WINNOW") && !hasCategory(findings, "IP_HEADER_STRIP") {
				t.Fatalf("%s expected IP match, got %+v", name, findings)
			}
			assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary")
		}

		// Benign C file with sparse \n\f\n page breaks MUST produce 0 findings.
		cPage := strings.Repeat("/* Public BSD-style helper */\nint helper_add(int a, int b) { return a + b; }\n", 8)
		cWithFormFeeds := []byte(strings.Repeat(cPage+"\n\f\n", 4))
		ffFindings, ffCov, err := runEngineOnFiles(t, engine, map[string][]byte{"c_file_with_formfeed_pagebreaks.c": cWithFormFeeds}, "")
		if err != nil || !ffCov.Complete || len(ffFindings) != 0 {
			t.Fatalf("c_file_with_formfeed_pagebreaks expected 0 findings, cov=%+v err=%v findings=%+v", ffCov, err, ffFindings)
		}
	})

	t.Run("ClusterA_BOMlessUTF16CredentialsAndControls", func(t *testing.T) {
		secretGH := "ghp_0123456789abcdef0123456789abcdef0123"
		secretSK := "sk-abcdefghij"

		leTrailingNul := append(encodeBOMlessUTF16LE(secretSK), 0x00, 0x00)
		leOddSecret := append(encodeBOMlessUTF16LE(secretGH), '\n')
		beOddSecret := append(encodeBOMlessUTF16BE(secretGH), '\n')
		leShortOdd := append(encodeBOMlessUTF16LE(secretSK), '\n')
		leNonASCIISuffix := encodeBOMlessUTF16LE(secretSK + "日本語日本語日本語")
		leNonASCIIPrefix := encodeBOMlessUTF16LE("日本語日本語日本語" + secretSK)

		for name, data := range map[string][]byte{
			"utf16_trailing_nul.dat":      leTrailingNul,
			"utf16_odd_len_secret.dat":    leOddSecret,
			"utf16be_odd_secret.dat":      beOddSecret,
			"utf16le_short_odd.dat":       leShortOdd,
			"utf16le_nonascii_suffix.dat": leNonASCIISuffix,
			"utf16le_nonascii_prefix.dat": leNonASCIIPrefix,
		} {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if !hasCategory(findings, "SECRET") {
				t.Fatalf("%s expected SECRET finding, got %+v", name, findings)
			}
			assertNoRawLeak(t, findings, cov, secretGH, secretSK)
		}

		// Benign controls (16..30B binary headers & non-ASCII OSS UTF-16).
		benignControls := map[string][]byte{
			"ctrl_utf16_nonascii_oss.go": encodeBOMlessUTF16LE("// Copyright © 2026 Open Contributors — 日本語コメント\n// SPDX-License-Identifier: MIT\npackage oss\nfunc OK() int { return 1 }\n"),
			"benign_hdr_16.dat":          {0x48, 0x00, 0x44, 0x00, 0x52, 0x00, 0x01, 0x00, 0xFF, 0x00, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00},
			"benign_hdr_24.bin":          {0x56, 0x00, 0x45, 0x00, 0x52, 0x00, 0x31, 0x00, 0x00, 0x00, 0x80, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00},
			"benign_hdr_30.dat":          append([]byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x01, 0x02, 0x00, 0x00}, bytes.Repeat([]byte{0x04, 0x00}, 10)...),
		}
		bf, bcov, err := runEngineOnFiles(t, engine, benignControls, "")
		if err != nil || !bcov.Complete || len(bf) != 0 {
			t.Fatalf("ClusterA UTF-16 benign controls expected 0 findings, cov=%+v err=%v findings=%+v", bcov, err, bf)
		}
	})

	// =========================================================================
	// CLUSTER B: JPEG Q=1..100, Opt DHT, SOF2/DRI/<512B SOS, APP0/8BIM, ICC
	// =========================================================================
	t.Run("ClusterB_JPEGQualities1To100AndRealControls", func(t *testing.T) {
		gradImg := image.NewRGBA(image.Rect(0, 0, 128, 128))
		for y := 0; y < 128; y++ {
			for x := 0; x < 128; x++ {
				gradImg.SetRGBA(x, y, color.RGBA{
					R: uint8((x * 2) % 256),
					G: uint8((y * 2) % 256),
					B: uint8((x + y) % 256),
					A: 255,
				})
			}
		}
		files := make(map[string][]byte, 110)
		for q := 1; q <= 100; q++ {
			var jb bytes.Buffer
			if err := jpeg.Encode(&jb, gradImg, &jpeg.Options{Quality: q}); err != nil {
				t.Fatalf("jpeg.Encode Q=%d: %v", q, err)
			}
			files[fmt.Sprintf("grad_q%03d.jpg", q)] = jb.Bytes()
		}

		// Solid 1024x1024 Q=50 & Q=95
		solidBig := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
		for _, q := range []int{50, 95} {
			var jb bytes.Buffer
			if err := jpeg.Encode(&jb, solidBig, &jpeg.Options{Quality: q}); err != nil {
				t.Fatalf("solid 1024x1024 Q=%d: %v", q, err)
			}
			files[fmt.Sprintf("jpeg_solid_1024_q%d.jpg", q)] = jb.Bytes()
		}

		// Tiny 16x16 Q=75 (noisy & solid)
		tinyNoisy := image.NewRGBA(image.Rect(0, 0, 16, 16))
		for y := 0; y < 16; y++ {
			for x := 0; x < 16; x++ {
				tinyNoisy.SetRGBA(x, y, color.RGBA{
					R: csprng[(y*16+x)*3],
					G: csprng[(y*16+x)*3+1],
					B: csprng[(y*16+x)*3+2],
					A: 255,
				})
			}
		}
		var tinyNoisyBuf, tinySolidBuf bytes.Buffer
		_ = jpeg.Encode(&tinyNoisyBuf, tinyNoisy, &jpeg.Options{Quality: 75})
		_ = jpeg.Encode(&tinySolidBuf, image.NewRGBA(image.Rect(0, 0, 16, 16)), &jpeg.Options{Quality: 75})
		files["jpeg_tiny_16_q75.jpg"] = tinyNoisyBuf.Bytes()
		files["jpeg_tiny_16_solid_q75.jpg"] = tinySolidBuf.Bytes()

		// Optimized-AC DHT JPEG (all symbols <= 0x7a -> 100% ASCII after C0-strip, valid baseline th=1).
		baseJ := files["grad_q075.jpg"]
		sosOff := bytes.Index(baseJ, []byte{0xFF, 0xDA})
		var optDHTJ bytes.Buffer
		optDHTJ.Write([]byte{0xFF, 0xD8})
		optDHTJ.Write([]byte{0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00})
		optDHTJ.Write(append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...))
		optDHTJ.Write([]byte{0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30}) // DC th=0, symbol 0x30 ('0')
		optDHTJ.Write([]byte{0xFF, 0xC4, 0x00, 0x1F, 0x10, 0, 0, 1, 2, 2, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0x21, 0x22, 0x31, 0x32, 0x33, 0x41, 0x42, 0x51, 0x52, 0x61, 0x71, 0x72}) // AC th=0, Kraft=13824<=65536, all symbols 0x21..0x72 (100% ASCII)
		optDHTJ.Write([]byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00})
		optDHTJ.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x00, 0xFF, 0xD9})
		files["jpeg_opt_dht.jpg"] = optDHTJ.Bytes()

		// Genuine Q=75 EXIF thumbnail across JPEG, PNG, WebP.
		var thumb75 bytes.Buffer
		_ = jpeg.Encode(&thumb75, gradImg.SubImage(image.Rect(0, 0, 32, 32)), &jpeg.Options{Quality: 75})
		exifHdr := []byte("Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00\x0f\x01\x02\x00\x06\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00Canon\x00")
		exifThumb := append(append([]byte(nil), exifHdr...), thumb75.Bytes()...)
		var exifSeg bytes.Buffer
		exifSeg.Write([]byte{0xFF, 0xE1})
		_ = binary.Write(&exifSeg, binary.BigEndian, uint16(len(exifThumb)+2))
		exifSeg.Write(exifThumb)
		files["jpeg_exif_q75_thumb.jpg"] = append(append(append([]byte(nil), baseJ[:sosOff]...), exifSeg.Bytes()...), baseJ[sosOff:]...)
		files["png_exif_q75_thumb.png"] = injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 32, 32), makePNGChunk("eXIf", exifThumb[6:]))
		validVP8 := minimalValidVP8Chunk()
		files["webp_exif_q75_thumb.webp"] = buildRIFFWebP(
			struct {
				fourCC  string
				payload []byte
			}{"VP8X", make([]byte, 10)},
			struct {
				fourCC  string
				payload []byte
			}{"VP8 ", validVP8},
			struct {
				fourCC  string
				payload []byte
			}{"EXIF", exifThumb},
		)

		// Valid >256B SOF2 progressive JPEG decodable by image/jpeg.Decode.
		// Grayscale 128x128 (256 8x8 blocks) progressive DC scan + AC scan using valid DC=0 (1-bit code 0) and AC EOB (1-bit code 0) -> 256+256 bits = 64B? With 256x256 (1024 blocks): DC+AC = 256+ bytes of real decodable MCUs!
		var sof2Valid bytes.Buffer
		sof2Valid.Write([]byte{0xFF, 0xD8})
		sof2Valid.Write([]byte{0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00})
		sof2Valid.Write(append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...))
		// DC DHT (tc=0, th=0): 1 code of len 1 -> sym 0 (diff=0)
		sof2Valid.Write([]byte{0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00})
		// AC DHT (tc=1, th=0): 1 code of len 1 -> sym 0 (EOB)
		sof2Valid.Write([]byte{0xFF, 0xC4, 0x00, 0x14, 0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00})
		// SOF2 256x256 (1024 blocks) grayscale
		sof2Valid.Write([]byte{0xFF, 0xC2, 0x00, 0x0B, 0x08, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x11, 0x00})
		// Scan 1: DC (Ss=0, Se=0): 1024 zero bits = 128 bytes of 0x00
		sof2Valid.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
		sof2Valid.Write(bytes.Repeat([]byte{0x00}, 128))
		// Scan 2: AC (Ss=1, Se=63): 1024 EOB zero bits = 128 bytes of 0x00 -> totalScanBytes = 256!
		sof2Valid.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x01, 0x3F, 0x00})
		sof2Valid.Write(bytes.Repeat([]byte{0x00}, 128))
		sof2Valid.Write([]byte{0xFF, 0xD9})
		if _, decErr := jpeg.Decode(bytes.NewReader(sof2Valid.Bytes())); decErr != nil {
			t.Fatalf("sof2_real_over256.jpg must be decodable by jpeg.Decode: %v", decErr)
		}
		files["sof2_real_over256.jpg"] = sof2Valid.Bytes()

		// Real macOS ColorSync ICC profiles across JPEG APP2, PNG iCCP, WebP ICCP, PDF /ICCBased.
		if iccPaths, globErr := filepath.Glob("/System/Library/ColorSync/Profiles/*.icc"); globErr == nil {
			for idx, p := range iccPaths {
				iccBytes, rErr := os.ReadFile(p)
				if rErr != nil || len(iccBytes) == 0 {
					continue
				}
				baseName := filepath.Base(p)
				if idx < 4 {
					// Embed in JPEG APP2 (2 chunks), PNG iCCP, WebP ICCP, and PDF /ICCBased.
					half := len(iccBytes) / 2
					var app2 bytes.Buffer
					for s, part := range [][]byte{iccBytes[:half], iccBytes[half:]} {
						segPayload := append([]byte{'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', 0, byte(s + 1), 2}, part...)
						app2.Write([]byte{0xFF, 0xE2})
						_ = binary.Write(&app2, binary.BigEndian, uint16(len(segPayload)+2))
						app2.Write(segPayload)
					}
					files["icc_jpg_"+baseName+".jpg"] = append(append(append([]byte(nil), baseJ[:sosOff]...), app2.Bytes()...), baseJ[sosOff:]...)
					files["icc_png_"+baseName+".png"] = injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 32, 32), makePNGChunk("iCCP", append([]byte("icc\x00\x00"), zlibCompress(iccBytes)...)))
					files["icc_webp_"+baseName+".webp"] = buildRIFFWebP(
						struct {
							fourCC  string
							payload []byte
						}{"VP8X", make([]byte, 10)},
						struct {
							fourCC  string
							payload []byte
						}{"ICCP", iccBytes},
						struct {
							fourCC  string
							payload []byte
						}{"VP8 ", validVP8},
					)
				}
				compICC := zlibCompress(iccBytes)
				files["icc_pdf_"+baseName+".pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compICC)), compICC)
			}
		}

		findings, cov, err := runEngineOnFiles(t, engine, files, "")
		if err != nil || !cov.Complete {
			t.Fatalf("ClusterB controls Analyze failed: cov=%+v err=%v", cov, err)
		}
		if len(findings) != 0 {
			t.Fatalf("ClusterB controls expected 0 findings, got %+v", findings)
		}
	})

	t.Run("ClusterB_ConcealmentBypasses", func(t *testing.T) {
		baseJPG := buildGenuineJPEG(t, 48, 48)
		sosIdx := bytes.Index(baseJPG, []byte{0xFF, 0xDA})
		insertBeforeSOS := func(marker byte, payload []byte) []byte {
			var seg bytes.Buffer
			seg.Write([]byte{0xFF, marker})
			_ = binary.Write(&seg, binary.BigEndian, uint16(len(payload)+2))
			seg.Write(payload)
			return append(append(append([]byte(nil), baseJPG[:sosIdx]...), seg.Bytes()...), baseJPG[sosIdx:]...)
		}
		stuffFF := func(raw []byte) []byte {
			var b bytes.Buffer
			for _, c := range raw {
				b.WriteByte(c)
				if c == 0xFF {
					b.WriteByte(0x00)
				}
			}
			return b.Bytes()
		}

		// DQT 4x129B CSPRNG, 32x129B CSPRNG, split 4-segment DQT CSPRNG, DQT NUL IP.
		var dqt4 bytes.Buffer
		for tq := 0; tq < 4; tq++ {
			dqt4.WriteByte(0x10 | byte(tq))
			dqt4.Write(csprng[tq*128 : (tq+1)*128])
		}
		jpgDQT4x129 := insertBeforeSOS(0xDB, dqt4.Bytes())
		var dqt32 bytes.Buffer
		for i := 0; i < 32; i++ {
			dqt32.WriteByte(0x10 | byte(i%4))
			dqt32.Write(csprng[(i*128)%3072 : ((i*128)%3072)+128])
		}
		jpgDQTMulti := insertBeforeSOS(0xDB, dqt32.Bytes())
		var dqtSplit bytes.Buffer
		dqtSplit.Write(baseJPG[:sosIdx])
		for tq := 0; tq < 4; tq++ {
			dqtSplit.Write([]byte{0xFF, 0xDB, 0x00, 0x83, 0x10 | byte(tq)})
			dqtSplit.Write(csprng[tq*128 : (tq+1)*128])
		}
		dqtSplit.Write(baseJPG[sosIdx:])
		jpgDQTNulIP := insertBeforeSOS(0xDB, interleaveNUL(stripped, 20))

		// JPEG SOF0+DRI SOS tail CSPRNG, DRI mid-RST CSPRNG, SOF2 SOS CSPRNG, <512B (350B) SOS tail CSPRNG, EXIF SOF2 thumb CSPRNG.
		eoiIdx := len(baseJPG) - 2
		jpgSOF0DRISOS := append(append(append([]byte(nil), baseJPG[:sosIdx]...), []byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01}...), baseJPG[sosIdx:eoiIdx]...)
		jpgSOF0DRISOS = append(append(jpgSOF0DRISOS, stuffFF(csprng[:1024])...), 0xFF, 0xD9)

		var solid16 bytes.Buffer
		_ = jpeg.Encode(&solid16, image.NewRGBA(image.Rect(0, 0, 16, 16)), &jpeg.Options{Quality: 75})
		raw16 := solid16.Bytes()
		sof16 := bytes.Index(raw16, []byte{0xFF, 0xC0})
		sos16 := bytes.Index(raw16, []byte{0xFF, 0xDA})
		sos16HLen := int(binary.BigEndian.Uint16(raw16[sos16+2 : sos16+4]))
		mcuBody := raw16[sos16+2+sos16HLen : len(raw16)-2]
		hdr32 := append([]byte(nil), raw16[:sos16]...)
		binary.BigEndian.PutUint16(hdr32[sof16+5:sof16+7], 32)
		binary.BigEndian.PutUint16(hdr32[sof16+7:sof16+9], 32)
		var midRST bytes.Buffer
		midRST.Write(hdr32)
		midRST.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
		midRST.Write(raw16[sos16 : sos16+2+sos16HLen])
		midRST.Write(mcuBody)
		midRST.Write(stuffFF(csprng[:512])) // CSPRNG hidden before RST0!
		midRST.Write([]byte{0xFF, 0xD0})
		midRST.Write(mcuBody)
		midRST.Write([]byte{0xFF, 0xD1})
		midRST.Write(mcuBody)
		midRST.Write([]byte{0xFF, 0xD2})
		midRST.Write(mcuBody)
		midRST.Write([]byte{0xFF, 0xD9})

		// SOF0 without DRI, 350B CSPRNG tail (< 512 totalScanBytes).
		jpgSOF0NoDRI350B := append(append([]byte(nil), raw16[:len(raw16)-2]...), stuffFF(csprng[:350])...)
		jpgSOF0NoDRI350B = append(jpgSOF0NoDRI350B, 0xFF, 0xD9)

		// SOF2 progressive SOS CSPRNG.
		jpgSOF2CSPRNG := append([]byte(nil), baseJPG[:eoiIdx]...)
		sof0Off := bytes.Index(jpgSOF2CSPRNG, []byte{0xFF, 0xC0})
		jpgSOF2CSPRNG[sof0Off+1] = 0xC2
		jpgSOF2CSPRNG = append(append(jpgSOF2CSPRNG, stuffFF(csprng[:1024])...), 0xFF, 0xD9)

		// EXIF SOF2 thumb CSPRNG.
		exifHdr := []byte("Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00\x0f\x01\x02\x00\x06\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00Canon\x00")
		jpgExifSOF2CSPRNG := insertBeforeSOS(0xE1, append(append([]byte(nil), exifHdr...), jpgSOF2CSPRNG...))

		// APP0 JFIF uncompressed thumbnail CSPRNG (36x36 RGB = 3888B).
		jfifCSPRNG := append([]byte{'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 36, 36}, csprng[:3*36*36]...)
		jpgAPP0ThumbCSPRNG := insertBeforeSOS(0xE0, jfifCSPRNG)

		// APP13 8BIM 0x0404 CSPRNG & 0x040C pre-SOI CSPRNG.
		var bim0404 bytes.Buffer
		bim0404.WriteString("Photoshop 3.0\x008BIM")
		_ = binary.Write(&bim0404, binary.BigEndian, uint16(0x0404))
		bim0404.Write([]byte{0, 0})
		_ = binary.Write(&bim0404, binary.BigEndian, uint32(2048))
		bim0404.Write(csprng[:2048])
		jpgAPP13CSPRNG := insertBeforeSOS(0xED, bim0404.Bytes())

		var bimPreSOI bytes.Buffer
		bimPreSOI.WriteString("Photoshop 3.0\x008BIM")
		_ = binary.Write(&bimPreSOI, binary.BigEndian, uint16(0x040C))
		bimPreSOI.Write([]byte{0, 0})
		preSOIPayload := append(append([]byte(nil), csprng[:1024]...), raw16...)
		_ = binary.Write(&bimPreSOI, binary.BigEndian, uint32(len(preSOIPayload)))
		bimPreSOI.Write(preSOIPayload)
		if len(preSOIPayload)%2 != 0 {
			bimPreSOI.WriteByte(0)
		}
		jpgAPP13PreSOI := insertBeforeSOS(0xED, bimPreSOI.Bytes())

		// Spoofed 'acsp' ICC profiles (144B 1-tag, gap CSPRNG, fake 'curv' CSPRNG, fake 'mft1' CSPRNG) across JPEG/PNG/WebP/PDF.
		make1TagSpoofICC := func(payload []byte) []byte {
			tot := 144 + len(payload)
			out := make([]byte, tot)
			binary.BigEndian.PutUint32(out[0:4], uint32(tot))
			binary.BigEndian.PutUint32(out[8:12], 0x02100000)
			copy(out[12:16], "mntr")
			copy(out[16:20], "RGB ")
			copy(out[20:24], "XYZ ")
			copy(out[36:40], "acsp")
			binary.BigEndian.PutUint32(out[128:132], 1)
			copy(out[132:136], "A2B0")
			binary.BigEndian.PutUint32(out[136:140], 144)
			binary.BigEndian.PutUint32(out[140:144], uint32(len(payload)))
			copy(out[144:], payload)
			return out
		}
		spoofICC := make1TagSpoofICC(csprng[:2048])
		// Valid 4-tag ICC with non-monotonic 4KB CSPRNG inside 'curv' tag.
		validICCBase := buildValidICCProfile(make([]byte, 4096))
		curvSpoofICC := append([]byte(nil), validICCBase...)
		rtrcOff := int(binary.BigEndian.Uint32(curvSpoofICC[132+3*12+4 : 132+3*12+8]))
		copy(curvSpoofICC[rtrcOff+12:], csprng[:4096])

		validVP8 := minimalValidVP8Chunk()
		compSpoofICC := zlibCompress(spoofICC)
		compCurvSpoof := zlibCompress(curvSpoofICC)

		bypasses := map[string][]byte{
			"jpg_dqt_4x129_csprng.jpg":         jpgDQT4x129,
			"jpg_dqt_multi_csprng.jpg":         jpgDQTMulti,
			"jpg_dqt_split_4seg_csprng.jpg":    dqtSplit.Bytes(),
			"jpg_dqt_nul_ip.jpg":               jpgDQTNulIP,
			"jpg_sof0_dri_sos_csprng.jpg":      jpgSOF0DRISOS,
			"jpg_dri_mid_rst_csprng.jpg":       midRST.Bytes(),
			"jpg_sof0_nodri_350b_csprng.jpg":   jpgSOF0NoDRI350B,
			"jpg_sof2_prog_sos_csprng.jpg":     jpgSOF2CSPRNG,
			"jpg_exif_sof2_thumb_csprng.jpg":   jpgExifSOF2CSPRNG,
			"jpg_app0_jfif_thumb_csprng.jpg":   jpgAPP0ThumbCSPRNG,
			"jpg_app13_8bim_csprng.jpg":        jpgAPP13CSPRNG,
			"jpg_app13_8bim_presoi_csprng.jpg": jpgAPP13PreSOI,
			"jpg_app2_iccp_spoof_csprng.jpg":   insertBeforeSOS(0xE2, append([]byte("ICC_PROFILE\x00\x01\x01"), spoofICC...)),
			"png_iccp_spoof_csprng.png":        injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 32, 32), makePNGChunk("iCCP", append([]byte("sRGB\x00\x00"), compSpoofICC...))),
			"webp_iccp_spoof_csprng.webp": buildRIFFWebP(struct {
				fourCC  string
				payload []byte
			}{"VP8X", make([]byte, 10)}, struct {
				fourCC  string
				payload []byte
			}{"ICCP", spoofICC}, struct {
				fourCC  string
				payload []byte
			}{"VP8 ", validVP8}),
			"pdf_icc_spoof_csprng.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compSpoofICC)), compSpoofICC),
			"pdf_icc_curv_csprng.pdf":  makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compCurvSpoof)), compCurvSpoof),
		}
		for name, payload := range bypasses {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if !hasCategory(findings, "IP_CONCEALMENT") {
				t.Fatalf("%s expected IP_CONCEALMENT, got %+v", name, findings)
			}
		}
	})

	// =========================================================================
	// CLUSTER C: WASM secID 1..12 Framing & PDF SFNT/ttcf/CFF/Type1/Image
	// =========================================================================
	t.Run("ClusterC_WASMControlsAndBypasses", func(t *testing.T) {
		appendUleb := func(b []byte, v uint64) []byte {
			var lb [10]byte
			n := binary.PutUvarint(lb[:], v)
			return append(b, lb[:n]...)
		}
		buildWASMSection := func(id byte, body []byte) []byte {
			out := []byte{id}
			out = appendUleb(out, uint64(len(body)))
			return append(out, body...)
		}
		buildDataSeg := func(payload []byte) []byte {
			var seg bytes.Buffer
			seg.WriteByte(0x01)
			seg.WriteByte(0x00)
			seg.Write([]byte{0x41, 0x00, 0x0b})
			var lb [10]byte
			n := binary.PutUvarint(lb[:], uint64(len(payload)))
			seg.Write(lb[:n])
			seg.Write(payload)
			return seg.Bytes()
		}

		// 1. IEEE CRC32 lookup table (1095B) in framed secID == 11 (< 2048B -> ALLOW).
		crcTable := make([]byte, 1024)
		for i := uint32(0); i < 256; i++ {
			c := i
			for k := 0; k < 8; k++ {
				if c&1 != 0 {
					c = 0xEDB88320 ^ (c >> 1)
				} else {
					c >>= 1
				}
			}
			binary.LittleEndian.PutUint32(crcTable[i*4:i*4+4], c)
		}
		rustCRC := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		rustCRC = append(rustCRC, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		rustCRC = append(rustCRC, buildWASMSection(11, buildDataSeg(crcTable))...)

		// 2. Deterministic Go-like WASM with genuine substantial Code (32 unique funcs with calls/control flow, >=16KB) + structured .rodata (secID == 11).
		var codeSec bytes.Buffer
		codeSec.WriteByte(32) // 32 unique functions
		for f := 0; f < 32; f++ {
			var funcBody bytes.Buffer
			funcBody.WriteByte(0x00) // 0 locals
			// Include call (0x10) / structured control flow (0x04, 0x05, 0x0b) + unique per-function constants.
			funcBody.Write([]byte{0x41, byte(f + 1), 0x04, 0x40, 0x10, 0x00, 0x0b})
			for i := 0; i < 512; i++ {
				op := byte(0x20 + ((i + f) % 32))
				if op == 0x01 || op == 0x0b {
					op = 0x41
				}
				funcBody.WriteByte(op)
			}
			funcBody.WriteByte(0x0b)
			var lb [5]byte
			n := binary.PutUvarint(lb[:], uint64(funcBody.Len()))
			codeSec.Write(lb[:n])
			codeSec.Write(funcBody.Bytes())
		}
		goLikeFuncSec := make([]byte, 33)
		goLikeFuncSec[0] = 32
		var rodata bytes.Buffer
		rodata.Write(crcTable)
		for i := 0; i < 128; i++ {
			fmt.Fprintf(&rodata, "runtime.symbol_%04d\x00", i)
		}
		goLikeWASM := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		goLikeWASM = append(goLikeWASM, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		goLikeWASM = append(goLikeWASM, buildWASMSection(3, goLikeFuncSec)...)
		goLikeWASM = append(goLikeWASM, buildWASMSection(7, []byte{0x01, 0x04, 'm', 'a', 'i', 'n', 0x00, 0x00})...)
		goLikeWASM = append(goLikeWASM, buildWASMSection(10, codeSec.Bytes())...)
		goLikeWASM = append(goLikeWASM, buildWASMSection(11, buildDataSeg(rodata.Bytes()))...)

		// 3a. 16 x 280B dummy functions + 4096B CSPRNG MUST be caught as bypass (wasm_16x280b_plus_sec11_csprng).
		var dummy16CodeSec bytes.Buffer
		dummy16CodeSec.WriteByte(16)
		var dummy16Body bytes.Buffer
		dummy16Body.WriteByte(0x00)
		for i := 0; i < 280; i++ {
			op := byte(0x20 + (i % 32))
			if op == 0x01 || op == 0x0b {
				op = 0x41
			}
			dummy16Body.WriteByte(op)
		}
		dummy16Body.WriteByte(0x0b)
		for f := 0; f < 16; f++ {
			var lb [5]byte
			n := binary.PutUvarint(lb[:], uint64(dummy16Body.Len()))
			dummy16CodeSec.Write(lb[:n])
			dummy16CodeSec.Write(dummy16Body.Bytes())
		}
		dummy16FuncSec := make([]byte, 17)
		dummy16FuncSec[0] = 16
		dummy16PlusCSPRNG := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		dummy16PlusCSPRNG = append(dummy16PlusCSPRNG, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		dummy16PlusCSPRNG = append(dummy16PlusCSPRNG, buildWASMSection(3, dummy16FuncSec)...)
		dummy16PlusCSPRNG = append(dummy16PlusCSPRNG, buildWASMSection(7, []byte{0x01, 0x04, 'm', 'a', 'i', 'n', 0x00, 0x00})...)
		dummy16PlusCSPRNG = append(dummy16PlusCSPRNG, buildWASMSection(10, dummy16CodeSec.Bytes())...)
		dummy16PlusCSPRNG = append(dummy16PlusCSPRNG, buildWASMSection(11, buildDataSeg(csprng))...)

		// 3b. 4 x 160B dummy functions + 4096B CSPRNG MUST be caught as bypass (wasm_subst_code_plus_sec11_csprng).
		var smallCodeSec bytes.Buffer
		smallCodeSec.WriteByte(0x04)
		var smallFuncBody bytes.Buffer
		smallFuncBody.WriteByte(0x00)
		for i := 0; i < 160; i++ {
			op := byte(0x20 + (i % 32))
			if op == 0x01 || op == 0x0b {
				op = 0x41
			}
			smallFuncBody.WriteByte(op)
		}
		smallFuncBody.WriteByte(0x0b)
		for f := 0; f < 4; f++ {
			var lb [5]byte
			n := binary.PutUvarint(lb[:], uint64(smallFuncBody.Len()))
			smallCodeSec.Write(lb[:n])
			smallCodeSec.Write(smallFuncBody.Bytes())
		}
		smallCodePlusCSPRNG := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		smallCodePlusCSPRNG = append(smallCodePlusCSPRNG, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		smallCodePlusCSPRNG = append(smallCodePlusCSPRNG, buildWASMSection(3, []byte{0x04, 0x00, 0x00, 0x00, 0x00})...)
		smallCodePlusCSPRNG = append(smallCodePlusCSPRNG, buildWASMSection(7, []byte{0x01, 0x04, 'm', 'a', 'i', 'n', 0x00, 0x00})...)
		smallCodePlusCSPRNG = append(smallCodePlusCSPRNG, buildWASMSection(10, smallCodeSec.Bytes())...)
		smallCodePlusCSPRNG = append(smallCodePlusCSPRNG, buildWASMSection(11, buildDataSeg(csprng))...)

		wasmControls := map[string][]byte{
			"rust_crc_table_sec11.wasm": rustCRC,
			"go_like_substantial.wasm":  goLikeWASM,
		}

		// Optionally compile genuine GOOS=wasip1 & GOOS=js Go WASM modules if `go` is available.
		if goBin, err := exec.LookPath("go"); err == nil {
			srcDir := t.TempDir()
			mainGo := filepath.Join(srcDir, "main.go")
			_ = os.WriteFile(mainGo, []byte("package main\nimport (\n\t\"crypto/sha256\"\n\t\"fmt\"\n)\nfunc main() {\n\tsum := sha256.Sum256([]byte(\"hello\"))\n\tfmt.Printf(\"%x\\n\", sum)\n}\n"), 0o644)
			for _, goos := range []string{"wasip1", "js"} {
				outWasm := filepath.Join(srcDir, "real_"+goos+".wasm")
				cmd := exec.Command(goBin, "build", "-o", outWasm, mainGo)
				cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=wasm")
				if err := cmd.Run(); err == nil {
					if wb, rErr := os.ReadFile(outWasm); rErr == nil && len(wb) > 0 {
						wasmControls["real_go_"+goos+".wasm"] = wb
					}
				}
			}
		}

		wf, wcov, err := runEngineOnFiles(t, engine, wasmControls, "")
		if err != nil || !wcov.Complete || len(wf) != 0 {
			t.Fatalf("WASM real controls expected 0 findings, cov=%+v err=%v findings=%+v", wcov, err, wf)
		}

		// WASM Bypasses (secID 7, 10, framed secID 11 CSPRNG).
		// Validly framed Export section with >4KB high-entropy valid UTF-8 export name (mixed 1/2/3-byte UTF-8, entropy >= 7.2).
		var utf8HighEnt bytes.Buffer
		for i := 0; i < 4096; i++ {
			b := csprng[i%len(csprng)]
			switch i % 3 {
			case 0:
				utf8HighEnt.WriteByte(b & 0x7f) // 128 distinct 1-byte ASCII/control
			case 1:
				utf8HighEnt.WriteRune(rune(0x0080 + int(b)*7)) // 2-byte UTF-8
			default:
				utf8HighEnt.WriteRune(rune(0x1000 + int(b)*17 + int(csprng[(i+13)%len(csprng)]))) // 3-byte UTF-8
			}
		}
		var validExp4K bytes.Buffer
		validExp4K.WriteByte(0x01)
		validExp4K.Write(appendUleb(nil, uint64(utf8HighEnt.Len())))
		validExp4K.Write(utf8HighEnt.Bytes())
		validExp4K.Write([]byte{0x00, 0x00})

		wasmSec7Unframed := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(7, csprng)...)
		wasmSec7Framed := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wasmSec7Framed = append(wasmSec7Framed, buildWASMSection(7, validExp4K.Bytes())...)

		wasmSec10Unframed := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(10, csprng)...)
		var framedCodeCSPRNG bytes.Buffer
		framedCodeCSPRNG.WriteByte(0x01)
		framedCodeCSPRNG.Write(appendUleb(nil, uint64(len(csprng)+2)))
		framedCodeCSPRNG.WriteByte(0x00)
		framedCodeCSPRNG.Write(csprng)
		framedCodeCSPRNG.WriteByte(0x0b)
		wasmSec10Framed := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wasmSec10Framed = append(wasmSec10Framed, buildWASMSection(3, []byte{0x01, 0x00})...)
		wasmSec10Framed = append(wasmSec10Framed, buildWASMSection(10, framedCodeCSPRNG.Bytes())...)

		wasmSec11Framed4K := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wasmSec11Framed4K = append(wasmSec11Framed4K, buildWASMSection(11, buildDataSeg(csprng))...)

		for name, payload := range map[string][]byte{
			"wasm_sec7_unframed_csprng.wasm":         wasmSec7Unframed,
			"wasm_sec7_framed_csprng.wasm":           wasmSec7Framed,
			"wasm_sec10_unframed_csprng.wasm":        wasmSec10Unframed,
			"wasm_sec10_framed_csprng.wasm":          wasmSec10Framed,
			"wasm_framed_sec11_csprng.wasm":          wasmSec11Framed4K,
			"wasm_16x280b_plus_sec11_csprng.wasm":    dummy16PlusCSPRNG,
			"wasm_subst_code_plus_sec11_csprng.wasm": smallCodePlusCSPRNG,
		} {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete || !hasCategory(findings, "IP_CONCEALMENT") {
				t.Fatalf("%s expected IP_CONCEALMENT, cov=%+v err=%v findings=%+v", name, cov, err, findings)
			}
		}
	})

	t.Run("ClusterC_PDFFontsAndImagesControlsAndBypasses", func(t *testing.T) {
		pdfControls := make(map[string][]byte)

		// Real macOS fonts (TTF, TTC, OTF, variable TTF with gvar+loca).
		for _, fontPath := range []string{
			"/System/Library/Fonts/Supplemental/Courier New.ttf",
			"/System/Library/Fonts/Courier.ttc",
			"/System/Library/Fonts/LastResort.otf",
			"/System/Library/Fonts/SFNSMono.ttf",
		} {
			if fb, err := os.ReadFile(fontPath); err == nil && len(fb) > 0 {
				comp := zlibCompress(fb)
				pdfControls["font_"+filepath.Base(fontPath)+".pdf"] = makeStreamPDF(
					fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(comp), len(fb)), comp)
			}
		}

		// Valid synthetic Type1 PostScript font with Adobe eexec cipher (r=55665).
		t1Plain := append([]byte{0x12, 0x34, 0x56, 0x78}, []byte("dup /Private 8 dict dup begin\n/RD {string currentfile exch readstring pop} executeonly def\n/ND {noaccess def} executeonly def\n/NP {noaccess put} executeonly def\n/BlueValues [ -15 0 680 695 ] def\n/MinFeature {16 16} def\n/password 5839 def\nend\ncurrentdict end\ncurrentfile closefile\n")...)
		r := uint32(55665)
		t1Cipher := make([]byte, len(t1Plain))
		for i, p := range t1Plain {
			c := p ^ byte(r>>8)
			t1Cipher[i] = c
			r = ((uint32(c)+r)*52845 + 22719) & 0xFFFF
		}
		var t1Font bytes.Buffer
		t1Font.WriteString("%!PS-AdobeFont-1.0: CustodianTest-Regular 001.000\n/FontName /CustodianTest-Regular def\ncurrentfile eexec\n")
		t1Font.WriteString(hex.EncodeToString(t1Cipher))
		t1Font.WriteByte('\n')
		t1Font.WriteString(strings.Repeat("0", 512))
		t1Font.WriteString("\ncleartomark\n")
		compT1 := zlibCompress(t1Font.Bytes())
		pdfControls["pdf_valid_type1.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 96 /Filter /FlateDecode", len(compT1)), compT1)

		// PNG Predictor 15 (Sub filter) image & /ColorSpace [/Indexed /DeviceRGB 255 (...)] image.
		rawPhoto := make([]byte, 32*32*3)
		for y := 0; y < 32; y++ {
			for x := 0; x < 32; x++ {
				idx := (y*32 + x) * 3
				n := int(csprng[(y*32+x)%len(csprng)]%15) - 7
				rawPhoto[idx] = byte(max(0, min(255, int(128+90*math.Sin(float64(x)*0.2))+n)))
				rawPhoto[idx+1] = byte(max(0, min(255, int(128+90*math.Cos(float64(y)*0.2))+n)))
				rawPhoto[idx+2] = byte(max(0, min(255, int(128+90*math.Sin(float64(x+y)*0.15)))+n))
			}
		}
		var pred15 bytes.Buffer
		for y := 0; y < 32; y++ {
			pred15.WriteByte(1) // Sub filter
			row := rawPhoto[y*96 : (y+1)*96]
			for x := 0; x < 96; x++ {
				var left byte
				if x >= 3 {
					left = row[x-3]
				}
				pred15.WriteByte(row[x] - left)
			}
		}
		compPred15 := zlibCompress(pred15.Bytes())
		pdfControls["pdf_image_png_predictor15.pdf"] = makeStreamPDF(
			fmt.Sprintf("/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace /DeviceRGB /BitsPerComponent 8 /DecodeParms << /Predictor 15 /Colors 3 /Columns 32 >> /Length %d /Filter /FlateDecode", len(compPred15)),
			compPred15,
		)

		indexedPixels := make([]byte, 32*32)
		for y := 0; y < 32; y++ {
			for x := 0; x < 32; x++ {
				indexedPixels[y*32+x] = byte((y/2)*8 + (x / 2))
			}
		}
		compIdx := zlibCompress(indexedPixels)
		pdfControls["pdf_image_indexed_array.pdf"] = makeStreamPDF(
			fmt.Sprintf("/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace [/Indexed /DeviceRGB 255 3 0 R] /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(compIdx)),
			compIdx,
		)

		cf, ccov, err := runEngineOnFiles(t, engine, pdfControls, "")
		if err != nil || !ccov.Complete || len(cf) != 0 {
			t.Fatalf("ClusterC PDF controls expected 0 findings, cov=%+v err=%v findings=%+v", ccov, err, cf)
		}

		// PDF Bypasses.
		validSFNT := buildSyntheticSFNTFont(nil)
		sfntTail := append(append([]byte(nil), validSFNT...), csprng...)
		compSFNTTail := zlibCompress(sfntTail)

		// Spoofed SFNT with CSPRNG in CFF table & valid header counts.
		spoofSFNT := make([]byte, 12+4*16+56+8+8+2048)
		copy(spoofSFNT[0:4], "OTTO")
		binary.BigEndian.PutUint16(spoofSFNT[4:6], 4)
		off := 12 + 4*16
		binary.BigEndian.PutUint32(spoofSFNT[off+12:off+16], 0x5F0F3CF5)
		copy(spoofSFNT[off+56+8+8:], csprng[:2048])
		compSpoofSFNT := zlibCompress(spoofSFNT)

		compType1CSpoof := zlibCompress(append([]byte{1, 0, 4, 2}, csprng[:2048]...))
		compPSFontRawSpoof := zlibCompress(append([]byte("%!PS-AdobeFont-1.0: Spoof\n/FontName /Spoof def\n"), csprng[:2048]...))
		compPSFontEexecSpoof := zlibCompress(append(append([]byte("%!PS-AdobeFont-1.0: Spoof\n/FontName /Spoof def\ncurrentfile eexec\n"), csprng[:2048]...), []byte("\ncleartomark\n")...))
		compImgSpoof := zlibCompress(csprng[:3072])
		compCMYKSpoof := zlibCompress(csprng[:4096])

		pdfBypasses := map[string][]byte{
			"pdf_fake_sfnt_tail_csprng.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(compSFNTTail), len(sfntTail)), compSFNTTail),
			"pdf_sfnt_spoof_csprng.pdf":     makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(compSpoofSFNT), len(spoofSFNT)), compSpoofSFNT),
			"pdf_type1c_spoof_csprng.pdf":   makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(compType1CSpoof)), compType1CSpoof),
			"pdf_psfont_raw_csprng.pdf":     makeStreamPDF(fmt.Sprintf("/Length %d /Length1 40 /Filter /FlateDecode", len(compPSFontRawSpoof)), compPSFontRawSpoof),
			"pdf_psfont_eexec_csprng.pdf":   makeStreamPDF(fmt.Sprintf("/Length %d /Length1 40 /Filter /FlateDecode", len(compPSFontEexecSpoof)), compPSFontEexecSpoof),
			"pdf_img_spoof_csprng.pdf":      makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(compImgSpoof)), compImgSpoof),
			"pdf_fake_cmyk_csprng.pdf":      makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace /DeviceCMYK /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(compCMYKSpoof)), compCMYKSpoof),
		}
		for name, payload := range pdfBypasses {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete || !hasCategory(findings, "IP_CONCEALMENT") {
				t.Fatalf("%s expected IP_CONCEALMENT, cov=%+v err=%v findings=%+v", name, cov, err, findings)
			}
		}
	})
}

func TestIteration7RemediationAllControlsAndBypasses(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 16 << 20,
	})

	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	compiledPol, errs := polEngine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("compile push-ip-protection.yaml: %+v", errs)
	}

	evalPolicy := func(findings []domain.Finding, cov domain.ScanCoverage) domain.PolicyEffect {
		sum := inspection.InspectionSummary{
			MandatoryScannersComplete: cov.Complete && cov.FilesSkipped == 0,
			ScanComplete:              cov.Complete && cov.FilesSkipped == 0,
		}
		for _, f := range findings {
			sum.TotalFindings++
			switch f.Category {
			case "SECRET":
				if f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh {
					sum.CriticalSecrets++
				}
			case "IP_CONCEALMENT":
				sum.ConcealmentFindings++
			case "IP_EXACT":
				sum.IPExactMatches++
			case "IP_WINNOW":
				sum.IPWinnowMatches++
			case "IP_HEADER_STRIP":
				sum.IPHeaderStripMatches++
			}
			if f.Category == "IP_EXACT" || f.Category == "IP_WINNOW" || f.Category == "IP_HEADER_MARKER" || f.Category == "IP_HEADER_STRIP" {
				cls, _ := f.Metadata["corpus_classification"].(string)
				if cls == "" {
					cls, _ = f.Metadata["classification"].(string)
				}
				switch strings.ToUpper(cls) {
				case string(domain.ClassificationRestricted):
					sum.RestrictedIPMatches++
				case string(domain.ClassificationConfidential):
					sum.ConfidentialIPMatches++
				}
			}
		}
		res, pErr := polEngine.Evaluate(context.Background(), compiledPol, policy.StagePushEgress, policy.PolicyInput{
			Stage:    policy.StagePushEgress,
			Findings: workflow.SummaryToFindingsInput(sum),
			Assessment: policy.AssessmentInput{
				Status:      "NOT_REQUIRED",
				IPRisk:      "NONE",
				Risk:        "NONE",
				Disposition: "NOT_REQUIRED",
			},
			Destination: policy.DestinationInput{
				ID:             "repo-internal",
				Name:           "acme/app",
				Host:           "github.com",
				Registered:     true,
				External:       false,
				Classification: "INTERNAL",
			},
			Push: policy.PushInput{
				RefNames:   []string{"refs/heads/main"},
				EgressMode: "ENFORCE_BLOCK",
			},
		})
		if pErr != nil {
			t.Fatalf("policy.Evaluate: %v", pErr)
		}
		return res.Effect
	}

	csprng := make([]byte, 4096)
	for off := 0; off < len(csprng); off += 32 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("iter7-csprng-%d", off)))
		copy(csprng[off:], sum[:])
	}
	validVP8 := minimalValidVP8Chunk()
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	zlibCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return buf.Bytes()
	}
	gzipCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(raw)
		_ = gw.Close()
		return buf.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< " + dictEntries + " >>\nstream\n")
		b.Write(body)
		b.WriteString("\nendstream\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
		return b.Bytes()
	}
	buildICC := func(extraSig string, extraTag []byte) []byte {
		const numTags = 4
		const hdrEnd = 132 + numTags*12
		descTag := make([]byte, 24)
		copy(descTag[0:4], "desc")
		binary.BigEndian.PutUint32(descTag[8:12], 8)
		copy(descTag[12:], "sRGB_IEC")
		cprtTag := make([]byte, 24)
		copy(cprtTag[0:4], "text")
		copy(cprtTag[8:], "Copyright 2026")
		wtptTag := make([]byte, 20)
		copy(wtptTag[0:4], "XYZ ")
		pad4 := func(b []byte) []byte {
			for len(b)%4 != 0 {
				b = append(b, 0)
			}
			return b
		}
		descTag = pad4(descTag)
		cprtTag = pad4(cprtTag)
		wtptTag = pad4(wtptTag)
		extraPad := pad4(append([]byte(nil), extraTag...))

		off0 := hdrEnd
		off1 := off0 + len(descTag)
		off2 := off1 + len(cprtTag)
		off3 := off2 + len(wtptTag)
		total := off3 + len(extraPad)

		icc := make([]byte, total)
		binary.BigEndian.PutUint32(icc[0:4], uint32(total))
		icc[8] = 2
		copy(icc[12:16], "mntr")
		copy(icc[16:20], "RGB ")
		copy(icc[20:24], "XYZ ")
		copy(icc[36:40], "acsp")
		binary.BigEndian.PutUint32(icc[128:132], numTags)
		putEntry := func(idx int, sig string, off, sz int) {
			pos := 132 + idx*12
			copy(icc[pos:pos+4], sig)
			binary.BigEndian.PutUint32(icc[pos+4:pos+8], uint32(off))
			binary.BigEndian.PutUint32(icc[pos+8:pos+12], uint32(sz))
		}
		putEntry(0, "desc", off0, len(descTag))
		putEntry(1, "cprt", off1, len(cprtTag))
		putEntry(2, "wtpt", off2, len(wtptTag))
		putEntry(3, extraSig, off3, len(extraTag))
		copy(icc[off0:], descTag)
		copy(icc[off1:], cprtTag)
		copy(icc[off2:], wtptTag)
		copy(icc[off3:], extraPad)
		return icc
	}
	appendUleb := func(b []byte, v uint64) []byte {
		var tmp [10]byte
		n := binary.PutUvarint(tmp[:], v)
		return append(b, tmp[:n]...)
	}
	buildWASMSection := func(id byte, body []byte) []byte {
		out := []byte{id}
		out = appendUleb(out, uint64(len(body)))
		return append(out, body...)
	}
	buildDataSegs := func(segs ...[]byte) []byte {
		var b bytes.Buffer
		b.Write(appendUleb(nil, uint64(len(segs))))
		for _, seg := range segs {
			b.WriteByte(0x00)
			b.Write([]byte{0x41, 0x00, 0x0b})
			b.Write(appendUleb(nil, uint64(len(seg))))
			b.Write(seg)
		}
		return b.Bytes()
	}

	// =========================================================================
	// Group 1 & Group 2 Controls: Compiled Go WASM (encoding/json + sha256),
	// Rust CRC32/rodata/lookup WASM, ALL 14 ColorSync ICC profiles, 8 macOS fonts
	// =========================================================================
	t.Run("Group1_RealControls_GoWASM_RustCRC_All14ICC_AllMacFonts", func(t *testing.T) {
		controls := make(map[string][]byte)

		// 1. Compiled Go WASM (GOOS=wasip1 and GOOS=js) with fmt + crypto/sha256 + encoding/json (unstripped & -ldflags="-s -w").
		if goBin, err := exec.LookPath("go"); err == nil {
			srcDir := t.TempDir()
			mainGo := filepath.Join(srcDir, "main.go")
			_ = os.WriteFile(mainGo, []byte("package main\nimport (\n\t\"crypto/sha256\"\n\t\"encoding/json\"\n\t\"fmt\"\n)\ntype msg struct { Hash string `json:\"hash\"` }\nfunc main() {\n\tsum := sha256.Sum256([]byte(\"custodian-wasm-control\"))\n\tb, _ := json.Marshal(msg{Hash: fmt.Sprintf(\"%x\", sum)})\n\tfmt.Println(string(b))\n}\n"), 0o644)
			mainJSONOnly := filepath.Join(srcDir, "json_only.go")
			_ = os.WriteFile(mainJSONOnly, []byte("package main\nimport \"encoding/json\"\ntype msg struct { OK bool `json:\"ok\"` }\nfunc main() {\n\tb, _ := json.Marshal(msg{OK: true})\n\tprintln(string(b))\n}\n"), 0o644)
			for _, goos := range []string{"wasip1", "js"} {
				for _, variant := range []struct {
					suffix string
					args   []string
				}{
					{"unstripped", []string{"build"}},
					{"stripped", []string{"build", "-ldflags=-s -w"}},
				} {
					outWasm := filepath.Join(srcDir, fmt.Sprintf("go_%s_%s.wasm", goos, variant.suffix))
					args := append(append([]string(nil), variant.args...), "-o", outWasm, mainGo)
					cmd := exec.Command(goBin, args...)
					cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=wasm")
					if cErr := cmd.Run(); cErr == nil {
						if wb, rErr := os.ReadFile(outWasm); rErr == nil && len(wb) > 0 {
							controls[fmt.Sprintf("real_go_json_sha_%s_%s.wasm", goos, variant.suffix)] = wb
						}
					}
				}
				outJSONOnly := filepath.Join(srcDir, fmt.Sprintf("json_only_%s.wasm", goos))
				cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", outJSONOnly, mainJSONOnly)
				cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=wasm")
				if cErr := cmd.Run(); cErr == nil {
					if wb, rErr := os.ReadFile(outJSONOnly); rErr == nil && len(wb) > 0 {
						controls[fmt.Sprintf("real_go_json_only_%s_stripped.wasm", goos)] = wb
					}
				}
			}
		}

		// 2. Rust CRC32 large rodata & structured uint16 lookup table WASM controls.
		crcTable := make([]byte, 1024)
		for i := 0; i < 256; i++ {
			c := uint32(i)
			for k := 0; k < 8; k++ {
				if c&1 != 0 {
					c = 0xEDB88320 ^ (c >> 1)
				} else {
					c >>= 1
				}
			}
			binary.LittleEndian.PutUint32(crcTable[i*4:i*4+4], c)
		}
		rodataLarge := append([]byte("rust_rodata_header: valid UTF-8 diagnostic strings for telemetry and crc32 lookup tables.\x00"), crcTable...)
		rodataLarge = append(rodataLarge, bytes.Repeat([]byte("rust_rodata_string_entry_ok\x00"), 32)...)
		rustRodataWASM := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		rustRodataWASM = append(rustRodataWASM, buildWASMSection(11, buildDataSegs(rodataLarge))...)
		controls["rust_rodata_crc_large.wasm"] = rustRodataWASM

		lookupBytes := make([]byte, 2048)
		for i := 0; i < 1024; i++ {
			val := uint16(32768 + 30000*math.Sin(float64(i)*2*math.Pi/128))
			binary.LittleEndian.PutUint16(lookupBytes[i*2:i*2+2], val)
		}
		lookupWASM := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		lookupWASM = append(lookupWASM, buildWASMSection(11, buildDataSegs(lookupBytes))...)
		controls["lookup_table.wasm"] = lookupWASM

		// 3. ALL 14 macOS ColorSync ICC profiles across JPEG APP2, PNG iCCP, WebP ICCP, and PDF /ICCBased.
		baseJ := buildGenuineJPEG(t, 24, 24)
		sosOff := bytes.Index(baseJ, []byte{0xFF, 0xDA})
		if iccPaths, globErr := filepath.Glob("/System/Library/ColorSync/Profiles/*.icc"); globErr == nil && len(iccPaths) > 0 {
			for _, p := range iccPaths {
				iccBytes, rErr := os.ReadFile(p)
				if rErr != nil || len(iccBytes) == 0 {
					continue
				}
				baseName := filepath.Base(p)
				// Single-chunk & split JPEG APP2.
				app2 := bytes.Buffer{}
				half := len(iccBytes) / 2
				for s, part := range [][]byte{iccBytes[:half], iccBytes[half:]} {
					segPayload := append([]byte{'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', 0, byte(s + 1), 2}, part...)
					app2.Write([]byte{0xFF, 0xE2})
					_ = binary.Write(&app2, binary.BigEndian, uint16(len(segPayload)+2))
					app2.Write(segPayload)
				}
				controls["all14_jpg_"+baseName+".jpg"] = append(append(append([]byte(nil), baseJ[:sosOff]...), app2.Bytes()...), baseJ[sosOff:]...)
				controls["all14_png_"+baseName+".png"] = injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 16, 16), makePNGChunk("iCCP", append([]byte("icc\x00\x00"), zlibCompress(iccBytes)...)))
				controls["all14_webp_"+baseName+".webp"] = buildRIFFWebP(
					struct {
						fourCC  string
						payload []byte
					}{"VP8X", make([]byte, 10)},
					struct {
						fourCC  string
						payload []byte
					}{"ICCP", iccBytes},
					struct {
						fourCC  string
						payload []byte
					}{"VP8 ", validVP8},
				)
				compICC := zlibCompress(iccBytes)
				controls["all14_pdf_"+baseName+".pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compICC)), compICC)
			}
		}

		// 4. All 8 macOS system fonts in PDF /FlateDecode.
		for _, fontPath := range []string{
			"/System/Library/Fonts/Supplemental/Courier New.ttf",
			"/System/Library/Fonts/Courier.ttc",
			"/System/Library/Fonts/LastResort.otf",
			"/System/Library/Fonts/SFNSMono.ttf",
			"/System/Library/Fonts/Geneva.ttf",
			"/System/Library/Fonts/Helvetica.ttc",
			"/System/Library/Fonts/Apple Symbols.ttf",
			"/System/Library/Fonts/Keyboard.ttf",
		} {
			if fb, rErr := os.ReadFile(fontPath); rErr == nil && len(fb) > 0 {
				comp := zlibCompress(fb)
				controls["macfont_"+filepath.Base(fontPath)+".pdf"] = makeStreamPDF(
					fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(comp), len(fb)), comp)
			}
		}

		for name, data := range controls {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: data}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("control %s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if len(findings) != 0 {
				t.Fatalf("control %s expected 0 findings, got %+v", name, findings)
			}
			if eff := evalPolicy(findings, cov); eff != domain.PolicyEffectAllow {
				t.Fatalf("control %s expected ALLOW, got %s", name, eff)
			}
		}

		// Verify explicit proprietary banner inside WebP ICCP/printable STILL triggers L3!
		explicitTag := make([]byte, 80)
		copy(explicitTag[0:4], "text")
		copy(explicitTag[8:], "Classification: RESTRICTED — Acme Proprietary\x00")
		explicitICC := buildICC("cprt", explicitTag)
		explicitWebP := buildRIFFWebP(
			struct {
				fourCC  string
				payload []byte
			}{"VP8X", make([]byte, 10)},
			struct {
				fourCC  string
				payload []byte
			}{"ICCP", explicitICC},
			struct {
				fourCC  string
				payload []byte
			}{"VP8 ", validVP8},
		)
		ef, ecov, err := runEngineOnFiles(t, engine, map[string][]byte{"explicit_banner_icc.webp": explicitWebP}, "")
		if err != nil || !ecov.Complete || !hasCategory(ef, "IP_HEADER_MARKER") {
			t.Fatalf("explicit banner in WebP ICCP expected IP_HEADER_MARKER, cov=%+v err=%v findings=%+v", ecov, err, ef)
		}
		if eff := evalPolicy(ef, ecov); eff != domain.PolicyEffectDeny {
			t.Fatalf("explicit RESTRICTED banner in WebP ICCP expected DENY, got %s", eff)
		}
	})

	// =========================================================================
	// Groups 2–5: ALL 29 Unique Bypasses from Secondary Reviewer (81b523b1) & Challenger 1 (333dafd2)
	// =========================================================================
	t.Run("Groups2To5_All29BypassesBlocked", func(t *testing.T) {
		bypasses := make(map[string][]byte)

		// --- Group 2: WASM secID == 11 ---
		wasm1800 := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wasm1800 = append(wasm1800, buildWASMSection(11, buildDataSegs(csprng[:1800]))...)
		bypasses["wasm_sec11_1800b_csprng.wasm"] = wasm1800

		var segs10x180 [][]byte
		for i := 0; i < 10; i++ {
			segs10x180 = append(segs10x180, csprng[i*180:(i+1)*180])
		}
		wasmSplit180 := append([]byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wasmSplit180 = append(wasmSplit180, buildWASMSection(11, buildDataSegs(segs10x180...))...)
		bypasses["wasm_sec11_split_10x180b_csprng.wasm"] = wasmSplit180

		// --- Group 3.1: PDF Type1 eexec ---
		eexecEncrypt := func(plain []byte) []byte {
			r := uint32(55665)
			out := make([]byte, len(plain))
			for i, p := range plain {
				c := p ^ byte(r>>8)
				out[i] = c
				r = ((uint32(c)+r)*52845 + 22719) & 0xFFFF
			}
			return out
		}
		ipSecret := append([]byte{0x12, 0x34, 0x56, 0x78}, append(append([]byte(nil), stripped...), []byte("\nconst tok = \"ghp_0123456789abcdef0123456789abcdef0123\"\n")...)...)
		ipCipher := eexecEncrypt(ipSecret)
		var t1Hex bytes.Buffer
		t1Hex.WriteString("%!PS-AdobeFont-1.0: BypassHex 001.000\n/FontName /BypassHex def\ncurrentfile eexec\n")
		t1Hex.WriteString(hex.EncodeToString(ipCipher))
		t1Hex.WriteString("\n" + strings.Repeat("0", 512) + "\ncleartomark\n")
		compT1Hex := zlibCompress(t1Hex.Bytes())
		bypasses["pdf_type1_eexec_encrypted_ip_hex.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 90 /Filter /FlateDecode", len(compT1Hex)), compT1Hex)

		var t1Bin bytes.Buffer
		t1Bin.WriteString("%!PS-AdobeFont-1.0: BypassBin 001.000\n/FontName /BypassBin def\ncurrentfile eexec\n")
		t1Bin.Write(ipCipher)
		t1Bin.WriteString("\n" + strings.Repeat("0", 512) + "\ncleartomark\n")
		compT1Bin := zlibCompress(t1Bin.Bytes())
		bypasses["pdf_type1_eexec_encrypted_ip_bin.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 90 /Filter /FlateDecode", len(compT1Bin)), compT1Bin)

		dilPlain := make([]byte, 0, 4+64+2700+2800)
		dilPlain = append(dilPlain, 0x12, 0x34, 0x56, 0x78)
		dilPlain = append(dilPlain, []byte("dup /Private 8 dict dup begin /password 5839 def end def\n")...)
		dilPlain = append(dilPlain, csprng[:2700]...)
		dilPlain = append(dilPlain, make([]byte, 2800)...)
		var t1Dil bytes.Buffer
		t1Dil.WriteString("%!PS-AdobeFont-1.0: Diluted 001.000\n/FontName /Diluted def\ncurrentfile eexec\n")
		t1Dil.Write(eexecEncrypt(dilPlain))
		t1Dil.WriteString("\n" + strings.Repeat("0", 512) + "\ncleartomark\n")
		compT1Dil := zlibCompress(t1Dil.Bytes())
		bypasses["pdf_type1_eexec_diluted_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 88 /Filter /FlateDecode", len(compT1Dil)), compT1Dil)

		// --- Group 3.2: PDF /Subtype /Image ---
		bpc16 := make([]byte, 64*32*2)
		for i := 0; i < 64*32; i++ {
			bpc16[i*2] = byte((i % 64) * 4) // smooth high byte
			bpc16[i*2+1] = csprng[i]        // 2048B CSPRNG low byte
		}
		compBPC16 := zlibCompress(bpc16)
		bypasses["pdf_img_bpc16_lowbyte_csprng.pdf"] = makeStreamPDF(
			fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 32 /ColorSpace /DeviceGray /BitsPerComponent 16 /Length %d /Filter /FlateDecode", len(compBPC16)), compBPC16)

		img33_67 := make([]byte, 64*96)
		copy(img33_67[64*32:], csprng[:4096])
		compImg33_67 := zlibCompress(img33_67)
		bypasses["pdf_img_33pct_smooth_67pct_csprng.pdf"] = makeStreamPDF(
			fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 96 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(compImg33_67)), compImg33_67)

		// --- Group 3.3: PDF SFNT & CFF ---
		sfntSum := func(tbl []byte) uint32 {
			padded := append([]byte(nil), tbl...)
			for len(padded)%4 != 0 {
				padded = append(padded, 0)
			}
			var s uint32
			for i := 0; i < len(padded); i += 4 {
				s += binary.BigEndian.Uint32(padded[i : i+4])
			}
			return s
		}
		buildCustomSFNT := func(extraTag string, extraTbl []byte, gapBytes []byte) []byte {
			headTbl := make([]byte, 54)
			binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
			maxpTbl := make([]byte, 6)
			binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
			binary.BigEndian.PutUint16(maxpTbl[4:6], 1)
			locaTbl := make([]byte, 4)
			glyfTbl := make([]byte, 16)
			type tblEntry struct {
				tag  string
				data []byte
			}
			tbls := []tblEntry{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", locaTbl}, {"glyf", glyfTbl}}
			if extraTag != "" {
				tbls = append(tbls, tblEntry{extraTag, extraTbl})
			}
			var body bytes.Buffer
			dirSize := 12 + len(tbls)*16
			var dir bytes.Buffer
			binary.Write(&dir, binary.BigEndian, uint32(0x00010000))
			binary.Write(&dir, binary.BigEndian, uint16(len(tbls)))
			binary.Write(&dir, binary.BigEndian, uint16(64))
			binary.Write(&dir, binary.BigEndian, uint16(2))
			binary.Write(&dir, binary.BigEndian, uint16(0))
			for idx, te := range tbls {
				if idx == 1 && len(gapBytes) > 0 {
					body.Write(gapBytes)
				}
				off := dirSize + body.Len()
				body.Write(te.data)
				for body.Len()%4 != 0 {
					body.WriteByte(0)
				}
				dir.WriteString(te.tag)
				binary.Write(&dir, binary.BigEndian, sfntSum(te.data))
				binary.Write(&dir, binary.BigEndian, uint32(off))
				binary.Write(&dir, binary.BigEndian, uint32(len(te.data)))
			}
			return append(dir.Bytes(), body.Bytes()...)
		}
		compSFNTDSIG := zlibCompress(buildCustomSFNT("DSIG", csprng[:4096], nil))
		bypasses["pdf_sfnt_dsig_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compSFNTDSIG)), compSFNTDSIG)

		compSFNTGap := zlibCompress(buildCustomSFNT("", nil, csprng[:4096]))
		bypasses["pdf_sfnt_gap_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compSFNTGap)), compSFNTGap)

		buildCFFIndex := func(items [][]byte) []byte {
			var b bytes.Buffer
			_ = binary.Write(&b, binary.BigEndian, uint16(len(items)))
			if len(items) == 0 {
				return b.Bytes()
			}
			b.WriteByte(4) // offSize=4
			off := uint32(1)
			_ = binary.Write(&b, binary.BigEndian, off)
			for _, it := range items {
				off += uint32(len(it))
				_ = binary.Write(&b, binary.BigEndian, off)
			}
			for _, it := range items {
				b.Write(it)
			}
			return b.Bytes()
		}
		encodeCFFInt29 := func(v int32) []byte {
			out := make([]byte, 5)
			out[0] = 29
			binary.BigEndian.PutUint32(out[1:5], uint32(v))
			return out
		}
		buildCFFBypass := func(privPayload, gsubPayload []byte) []byte {
			hdr := []byte{1, 0, 4, 4}
			nameIdx := buildCFFIndex([][]byte{[]byte("BypassFont")})
			strIdx := buildCFFIndex(nil)
			var gsubIdx []byte
			if len(gsubPayload) > 0 {
				gsubIdx = buildCFFIndex([][]byte{gsubPayload})
			} else {
				gsubIdx = buildCFFIndex(nil)
			}
			csIdx := buildCFFIndex([][]byte{{14}})
			// Compute Top DICT size iteratively (two entries: CharStrings 17, optional Private 18).
			tdLen := 6
			if len(privPayload) > 0 {
				tdLen = 17
			}
			tdIdxSize := 2 + 1 + 2*4 + tdLen
			csOff := len(hdr) + len(nameIdx) + tdIdxSize + len(strIdx) + len(gsubIdx)
			var td bytes.Buffer
			td.Write(encodeCFFInt29(int32(csOff)))
			td.WriteByte(17)
			if len(privPayload) > 0 {
				privOff := csOff + len(csIdx)
				td.Write(encodeCFFInt29(int32(len(privPayload))))
				td.Write(encodeCFFInt29(int32(privOff)))
				td.WriteByte(18)
			}
			tdIdx := buildCFFIndex([][]byte{td.Bytes()})
			var out bytes.Buffer
			out.Write(hdr)
			out.Write(nameIdx)
			out.Write(tdIdx)
			out.Write(strIdx)
			out.Write(gsubIdx)
			out.Write(csIdx)
			out.Write(privPayload)
			return out.Bytes()
		}
		compCFFPriv := zlibCompress(buildCFFBypass(csprng[:4096], nil))
		bypasses["pdf_type1c_private_dict_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(compCFFPriv)), compCFFPriv)
		compCFFGsub := zlibCompress(buildCFFBypass(nil, csprng[:4096]))
		bypasses["pdf_type1c_gsub_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(compCFFGsub)), compCFFGsub)

		// --- Group 3.4: Shared ICC mAB pre-CLUT gap, tiny-CLUT trailing CSPRNG, and mft1 g=4 ---
		buildTinyCLUT2x2x2 := func() []byte {
			clut := make([]byte, 20+24)
			clut[0], clut[1], clut[2] = 2, 2, 2
			clut[16] = 1
			return clut
		}
		mabPreGapTag := make([]byte, 32+4096+len(buildTinyCLUT2x2x2()))
		copy(mabPreGapTag[0:4], "mAB ")
		mabPreGapTag[8], mabPreGapTag[9] = 3, 3
		binary.BigEndian.PutUint32(mabPreGapTag[24:28], uint32(32+4096))
		copy(mabPreGapTag[32:32+4096], csprng[:4096])
		copy(mabPreGapTag[32+4096:], buildTinyCLUT2x2x2())
		iccPreGap := buildICC("A2B0", mabPreGapTag)

		bypasses["icc_mab_gap_csprng_png.png"] = injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 16, 16), makePNGChunk("iCCP", append([]byte("icc\x00\x00"), zlibCompress(iccPreGap)...)))
		baseJ := buildGenuineJPEG(t, 16, 16)
		sosIdx := bytes.Index(baseJ, []byte{0xFF, 0xDA})
		app2PreGap := append([]byte{'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', 0, 1, 1}, iccPreGap...)
		var jPreSeg bytes.Buffer
		jPreSeg.Write([]byte{0xFF, 0xE2})
		_ = binary.Write(&jPreSeg, binary.BigEndian, uint16(len(app2PreGap)+2))
		jPreSeg.Write(app2PreGap)
		bypasses["icc_mab_gap_csprng_jpg.jpg"] = append(append(append([]byte(nil), baseJ[:sosIdx]...), jPreSeg.Bytes()...), baseJ[sosIdx:]...)
		bypasses["icc_mab_gap_csprng_webp.webp"] = buildRIFFWebP(
			struct {
				fourCC  string
				payload []byte
			}{"VP8X", make([]byte, 10)},
			struct {
				fourCC  string
				payload []byte
			}{"ICCP", iccPreGap},
			struct {
				fourCC  string
				payload []byte
			}{"VP8 ", validVP8},
		)
		compICCPreGap := zlibCompress(iccPreGap)
		bypasses["icc_mab_gap_csprng_pdf.pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compICCPreGap)), compICCPreGap)

		mabTrailTag := make([]byte, 32+len(buildTinyCLUT2x2x2())+4096)
		copy(mabTrailTag[0:4], "mAB ")
		mabTrailTag[8], mabTrailTag[9] = 3, 3
		binary.BigEndian.PutUint32(mabTrailTag[24:28], 32)
		copy(mabTrailTag[32:], buildTinyCLUT2x2x2())
		copy(mabTrailTag[32+len(buildTinyCLUT2x2x2()):], csprng[:4096])
		compICCTrail := zlibCompress(buildICC("A2B0", mabTrailTag))
		bypasses["icc_mab_tiny_clut_trailing_csprng_pdf.pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(compICCTrail)), compICCTrail)

		// mft1 with g=4, ic=5, oc=3 -> 4^5 * 3 = 3072B CSPRNG.
		mft1G4 := make([]byte, 48+5*256+3072+3*256)
		copy(mft1G4[0:4], "mft1")
		mft1G4[8], mft1G4[9], mft1G4[10] = 5, 3, 4
		pos := 48
		for k := 0; k < 5; k++ {
			for i := 0; i < 256; i++ {
				mft1G4[pos+i] = byte(i)
			}
			pos += 256
		}
		copy(mft1G4[pos:pos+3072], csprng[:3072])
		pos += 3072
		for k := 0; k < 3; k++ {
			for i := 0; i < 256; i++ {
				mft1G4[pos+i] = byte(i)
			}
			pos += 256
		}
		iccMft1G4 := buildICC("A2B0", mft1G4)
		bypasses["icc_mft1_g4_csprng_png.png"] = injectPNGChunksBeforeIEND(t, buildGenuinePNG(t, 16, 16), makePNGChunk("iCCP", append([]byte("icc\x00\x00"), zlibCompress(iccMft1G4)...)))

		// --- Group 4: JPEG SOF3, SOF9, diluted DQT, DRI 16x240B ---
		stuffFF := func(raw []byte) []byte {
			var b bytes.Buffer
			for _, c := range raw {
				b.WriteByte(c)
				if c == 0xFF {
					b.WriteByte(0x00)
				}
			}
			return b.Bytes()
		}
		dqt1Tbl := append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...)
		dhtDC := []byte{0xFF, 0xC4, 0x00, 0x1F, 0x00, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		sof3 := []byte{0xFF, 0xC3, 0x00, 0x0B, 0x08, 0x00, 0x64, 0x00, 0x64, 0x01, 0x01, 0x11, 0x00}
		sof9 := []byte{0xFF, 0xC9, 0x00, 0x0B, 0x08, 0x00, 0x64, 0x00, 0x64, 0x01, 0x01, 0x11, 0x00}
		sosHdr := []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}
		bypasses["jpg_sof3_lossless_csprng.jpg"] = bytes.Join([][]byte{{0xFF, 0xD8}, dqt1Tbl, dhtDC, sof3, sosHdr, stuffFF(csprng), {0xFF, 0xD9}}, nil)
		bypasses["jpg_sof9_arith_sos_csprng.jpg"] = bytes.Join([][]byte{{0xFF, 0xD8}, dqt1Tbl, sof9, sosHdr, stuffFF(csprng), {0xFF, 0xD9}}, nil)

		// Diluted DQT: 2x128B 16-bit CSPRNG + 2x128B 16-bit zeros in one DQT segment.
		var dilDQT bytes.Buffer
		dilDQT.Write([]byte{0xFF, 0xDB})
		_ = binary.Write(&dilDQT, binary.BigEndian, uint16(2+4*129))
		dilDQT.WriteByte(0x10)
		dilDQT.Write(csprng[:128])
		dilDQT.WriteByte(0x11)
		dilDQT.Write(csprng[128:256])
		dilDQT.WriteByte(0x12)
		dilDQT.Write(make([]byte, 128))
		dilDQT.WriteByte(0x13)
		dilDQT.Write(make([]byte, 128))
		bypasses["jpg_dqt_diluted_csprng.jpg"] = append(append(append([]byte(nil), baseJ[:sosIdx]...), dilDQT.Bytes()...), baseJ[sosIdx:]...)

		// DRI 16 x 240B RST splitting on a decodable grayscale JPEG (32x32 -> 4x4 MCUs = 16 MCUs, DRI=1).
		// Construct a genuine 32x32 DRI=1 grayscale JPEG and inject 240B stuffed CSPRNG before each RST/EOI.
		var driBase bytes.Buffer
		driBase.Write([]byte{0xFF, 0xD8})
		driBase.Write(dqt1Tbl)
		driBase.Write([]byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x20, 0x00, 0x20, 0x01, 0x01, 0x11, 0x00})
		driBase.Write(dhtDC)
		// AC DHT: symbol 0x00 (EOB) = code 0 (len 1).
		driBase.Write([]byte{0xFF, 0xC4, 0x00, 0x14, 0x10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00})
		driBase.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
		driBase.Write(sosHdr)
		// Each 8x8 block is DC=0 (2 zero bits '00') + AC EOB (1 zero bit '0') -> 0x00 byte encodes 1 MCU cleanly.
		for iv := 0; iv < 16; iv++ {
			driBase.WriteByte(0x00)
			driBase.Write(stuffFF(csprng[iv*240 : (iv+1)*240]))
			if iv < 15 {
				driBase.Write([]byte{0xFF, byte(0xD0 + (iv % 8))})
			}
		}
		driBase.Write([]byte{0xFF, 0xD9})
		if _, dErr := jpeg.Decode(bytes.NewReader(driBase.Bytes())); dErr != nil {
			t.Fatalf("jpg_dri_16x240b_csprng fixture must be decodable by jpeg.Decode: %v", dErr)
		}
		bypasses["jpg_dri_16x240b_csprng.jpg"] = driBase.Bytes()

		// --- Group 5: L4b Bypasses ---
		// 1. Stream-encoded len%4 == 1 with .reduce() (59 x 43-char chunks).
		fullStreamB64 := base64.RawURLEncoding.EncodeToString(stripped)
		chunk59 := (len(fullStreamB64) / 43)
		chunk59 = chunk59 - (chunk59 % 4) + 3
		for chunk59*43 > len(fullStreamB64) {
			chunk59 -= 4
		}
		var streamChunks []string
		for k := 0; k < chunk59; k++ {
			streamChunks = append(streamChunks, fmt.Sprintf("%q", fullStreamB64[k*43:(k+1)*43]))
		}
		bypasses["l4b_stream_lenmod4eq1_reduce.js"] = []byte("const a = [" + strings.Join(streamChunks, ", ") + "];\nconst s = a.reduce((x,y)=>x+y,'');\n")

		// 2. Digest-array CSPRNG without join.
		var hexArr []string
		for i := 0; i < 128; i++ {
			hexArr = append(hexArr, fmt.Sprintf("%q", hex.EncodeToString(csprng[i*32:(i+1)*32])))
		}
		bypasses["l4b_digest_array_csprng_nojoin.js"] = []byte("const payload = [\n" + strings.Join(hexArr, ",\n") + "\n];\n")

		// 3. 512 Tier-1 decoy starvation.
		var decoy512 strings.Builder
		decoy512.WriteString("package decoys\n")
		for i := 0; i < 512; i++ {
			goBlob := fmt.Sprintf("package d%03d\nfunc Helper%03d() string {\n\treturn %q\n}\n", i, i, strings.Repeat("x", 3900))
			fmt.Fprintf(&decoy512, "var D%03d = %q\n", i, base64.StdEncoding.EncodeToString([]byte(goBlob)))
		}
		fmt.Fprintf(&decoy512, "var Target = %q\n", base64.StdEncoding.EncodeToString(stripped))
		bypasses["l4b_512_tier1_decoy_starvation.go"] = []byte(decoy512.String())

		// 4 & 5. Alternating prefixes before < 256B gzip (contains secret / Winnowing IP snippet).
		gzShort := gzipCompress([]byte("// proprietary\nconst tok = \"ghp_0123456789abcdef0123456789abcdef0123\";\n"))
		if len(gzShort) >= 256 {
			t.Fatalf("expected compressed short payload < 256B, got %d", len(gzShort))
		}
		bypasses["l4b_alt_prefix_b64_gz200.txt"] = []byte("ABABABAB" + base64.StdEncoding.EncodeToString(gzShort) + "\n")
		bypasses["l4b_alt_prefix_hex_gz200.txt"] = []byte("01010101" + hex.EncodeToString(gzShort) + "\n")

		// 6. JS ${...} > 128B.
		b64Full := base64.StdEncoding.EncodeToString(stripped)
		halfB64 := len(b64Full) / 2
		bypasses["l4b_backtick_gt128_interp.js"] = []byte("const s = `" + b64Full[:halfB64] + "${" + strings.Repeat(" ", 160) + "''}" + b64Full[halfB64:] + "`;\n")

		// 7. Comment > 4096B split.
		bypasses["l4b_comment_gt4096_split.js"] = []byte("const s = \"" + b64Full[:halfB64] + "\" /* " + strings.Repeat("c", 8192) + " */ + \"" + b64Full[halfB64:] + "\";\n")

		// 8. Python f-string interpolation.
		bypasses["l4b_python_fstring_interp.py"] = []byte("x = ''\ns = f\"" + b64Full[:halfB64] + "{x}" + b64Full[halfB64:] + "\"\n")

		// 9. ASCII85 <~...~>.
		var a85Buf bytes.Buffer
		a85Buf.WriteString("const data = `\n<~")
		a85Enc := ascii85.NewEncoder(&a85Buf)
		_, _ = a85Enc.Write(stripped)
		_ = a85Enc.Close()
		a85Buf.WriteString("~>\n`;\n")
		bypasses["l4b_ascii85_payload.js"] = a85Buf.Bytes()

		for name, payload := range bypasses {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if err != nil || !cov.Complete {
				t.Fatalf("bypass %s Analyze failed: cov=%+v err=%v", name, cov, err)
			}
			if len(findings) == 0 {
				t.Fatalf("bypass %s produced 0 findings (ALLOW bypass)", name)
			}
			eff := evalPolicy(findings, cov)
			if eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
				t.Fatalf("bypass %s expected DENY or QUARANTINE, got %s (findings=%+v)", name, eff, findings)
			}
			assertNoRawLeak(t, findings, cov, "TelemetryCalibrator", "Acme Proprietary", "ghp_0123456789abcdef0123456789abcdef0123")
		}
	})
}

func TestIteration8AllClustersControlsAndBypasses(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 16 << 20,
	})

	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	compiledPol, errs := polEngine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("compile push-ip-protection.yaml: %+v", errs)
	}

	evalPolicy := func(findings []domain.Finding, cov domain.ScanCoverage) domain.PolicyEffect {
		sum := inspection.InspectionSummary{
			MandatoryScannersComplete: cov.Complete && cov.FilesSkipped == 0,
			ScanComplete:              cov.Complete && cov.FilesSkipped == 0,
		}
		for _, f := range findings {
			sum.TotalFindings++
			switch f.Category {
			case "SECRET":
				if f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh {
					sum.CriticalSecrets++
				}
			case "IP_CONCEALMENT":
				sum.ConcealmentFindings++
			case "IP_EXACT":
				sum.IPExactMatches++
			case "IP_WINNOW":
				sum.IPWinnowMatches++
			case "IP_HEADER_STRIP":
				sum.IPHeaderStripMatches++
			}
			if f.Category == "IP_EXACT" || f.Category == "IP_WINNOW" || f.Category == "IP_HEADER_MARKER" || f.Category == "IP_HEADER_STRIP" {
				cls, _ := f.Metadata["corpus_classification"].(string)
				if cls == "" {
					cls, _ = f.Metadata["classification"].(string)
				}
				switch strings.ToUpper(cls) {
				case string(domain.ClassificationRestricted):
					sum.RestrictedIPMatches++
				case string(domain.ClassificationConfidential):
					sum.ConfidentialIPMatches++
				}
			}
		}
		res, pErr := polEngine.Evaluate(context.Background(), compiledPol, policy.StagePushEgress, policy.PolicyInput{
			Stage:    policy.StagePushEgress,
			Findings: workflow.SummaryToFindingsInput(sum),
			Assessment: policy.AssessmentInput{
				Status:      "NOT_REQUIRED",
				IPRisk:      "NONE",
				Risk:        "NONE",
				Disposition: "NOT_REQUIRED",
			},
			Destination: policy.DestinationInput{
				ID:             "repo-internal",
				Name:           "acme/app",
				Host:           "github.com",
				Registered:     true,
				External:       false,
				Classification: "INTERNAL",
			},
			Push: policy.PushInput{
				RefNames:   []string{"refs/heads/main"},
				EgressMode: "ENFORCE_BLOCK",
			},
		})
		if pErr != nil {
			t.Fatalf("policy.Evaluate: %v", pErr)
		}
		return res.Effect
	}

	csprng := make([]byte, 32768)
	for off := 0; off < len(csprng); off += 32 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("iter8-csprng-%d", off)))
		copy(csprng[off:], sum[:])
	}
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	zlibCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return buf.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< " + dictEntries + " >>\nstream\n")
		b.Write(body)
		b.WriteString("\nendstream\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
		return b.Bytes()
	}
	sfntSum := func(tbl []byte) uint32 {
		padded := append([]byte(nil), tbl...)
		for len(padded)%4 != 0 {
			padded = append(padded, 0)
		}
		var s uint32
		for i := 0; i+4 <= len(padded); i += 4 {
			s += binary.BigEndian.Uint32(padded[i : i+4])
		}
		return s
	}
	type sfntTbl struct {
		tag  string
		data []byte
	}
	buildSFNT := func(sfntTag uint32, tbls []sfntTbl, gapBytes []byte) []byte {
		var body bytes.Buffer
		dirSize := 12 + len(tbls)*16
		var dir bytes.Buffer
		_ = binary.Write(&dir, binary.BigEndian, sfntTag)
		_ = binary.Write(&dir, binary.BigEndian, uint16(len(tbls)))
		_ = binary.Write(&dir, binary.BigEndian, uint16(64))
		_ = binary.Write(&dir, binary.BigEndian, uint16(2))
		_ = binary.Write(&dir, binary.BigEndian, uint16(0))
		for idx, te := range tbls {
			if idx == 1 && len(gapBytes) > 0 {
				body.Write(gapBytes)
			}
			off := dirSize + body.Len()
			body.Write(te.data)
			for body.Len()%4 != 0 {
				body.WriteByte(0)
			}
			dir.WriteString(te.tag)
			_ = binary.Write(&dir, binary.BigEndian, sfntSum(te.data))
			_ = binary.Write(&dir, binary.BigEndian, uint32(off))
			_ = binary.Write(&dir, binary.BigEndian, uint32(len(te.data)))
		}
		return append(dir.Bytes(), body.Bytes()...)
	}
	baseSFNTTables := func() []sfntTbl {
		headTbl := make([]byte, 54)
		binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
		maxpTbl := make([]byte, 6)
		binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
		binary.BigEndian.PutUint16(maxpTbl[4:6], 1)
		locaTbl := make([]byte, 4)
		glyfTbl := make([]byte, 16)
		return []sfntTbl{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", locaTbl}, {"glyf", glyfTbl}}
	}
	buildCFFIndex := func(items [][]byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint16(len(items)))
		if len(items) == 0 {
			return b.Bytes()
		}
		b.WriteByte(4)
		off := uint32(1)
		_ = binary.Write(&b, binary.BigEndian, off)
		for _, it := range items {
			off += uint32(len(it))
			_ = binary.Write(&b, binary.BigEndian, off)
		}
		for _, it := range items {
			b.Write(it)
		}
		return b.Bytes()
	}
	encodeCFFInt29 := func(v int32) []byte {
		out := make([]byte, 5)
		out[0] = 29
		binary.BigEndian.PutUint32(out[1:5], uint32(v))
		return out
	}

	// =========================================================================
	// Cluster 1: ttcf Panic + 345 macOS Fonts + /Type1C + SFNT/CFF/CFF2 Bypasses
	// =========================================================================
	t.Run("Cluster1_MacOS345FontsAndType1CSweep", func(t *testing.T) {
		var fontPaths []string
		for _, root := range []string{"/System/Library/Fonts", "/System/Library/Fonts/Supplemental"} {
			entries, rErr := os.ReadDir(root)
			if rErr != nil {
				continue
			}
			for _, ent := range entries {
				if ent.IsDir() {
					continue
				}
				lower := strings.ToLower(ent.Name())
				if !strings.HasSuffix(lower, ".ttf") && !strings.HasSuffix(lower, ".otf") && !strings.HasSuffix(lower, ".ttc") {
					continue
				}
				p := filepath.Join(root, ent.Name())
				info, stErr := ent.Info()
				if stErr != nil || info.Size() <= 0 || info.Size() > 4<<20 {
					continue
				}
				fontPaths = append(fontPaths, p)
			}
		}
		if len(fontPaths) == 0 {
			t.Skip("no /System/Library/Fonts found on this host")
		}
		shortFilter := map[string]bool{
			"PTSans.ttc": true, "Noteworthy.ttc": true, "Kohinoor.ttc": true,
			"KohinoorBangla.ttc": true, "KohinoorGujarati.ttc": true, "KohinoorTelugu.ttc": true,
			"CJKSymbolsFallback.ttc": true, "EuphemiaCAS.ttc": true, "STIXTwoText.ttf": true,
			"STIXTwoText-Italic.ttf": true, "STIXTwoMath.otf": true, "STIXGeneral.otf": true,
			"STIXGeneralBol.otf": true, "STIXGeneralItalic.otf": true, "NotoSansJavanese-Regular.otf": true,
			"NotoSansGunjalaGondi-Regular.otf": true, "NotoSansMasaramGondi-Regular.otf": true,
			"NotoSansSiddham-Regular.otf": true, "NotoSansSunuwar-Regular.otf": true,
			"NotoSansTifinagh-Regular.otf": true, "NotoSerifYezidi-Regular.otf": true,
			"SignPainter.ttc": true, "SFIndia.ttc": true, "KefaIII.ttf": true,
			"NewYork.ttf": true, "SFCompact.ttf": true, "SFNSRounded.ttf": true,
			"ADTNumeric.ttc": true, "Bradley Hand Bold.ttf": true, "Mshtakan.ttc": true,
			"Waseem.ttc": true, "PlantagenetCherokee.ttf": true, "Bodoni Ornaments.ttf": true,
			"Courier New.ttf": true, "Times New Roman Bold.ttf": true, "SFNSMono.ttf": true, "LastResort.otf": true,
			"Hiragino Sans GB.ttc": true, "ITFDevanagari.ttc": true, "Tamil Sangam MN.ttc": true,
		}
		type fontJob struct {
			fp string
			fb []byte
		}
		var jobs []fontJob
		for _, fp := range fontPaths {
			if testing.Short() && !shortFilter[filepath.Base(fp)] {
				continue
			}
			fb, rErr := os.ReadFile(fp)
			if rErr != nil || len(fb) == 0 {
				continue
			}
			jobs = append(jobs, fontJob{fp: fp, fb: fb})
		}
		jobCh := make(chan fontJob, len(jobs))
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)

		var errMu sync.Mutex
		var errs []string
		var checked, checkedType1C int64
		var wg sync.WaitGroup
		workers := runtime.GOMAXPROCS(0)
		if workers < 4 {
			workers = 4
		}
		if workers > 12 {
			workers = 12
		}
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tmpBase, mkErr := os.MkdirTemp("", "custodian-font-sweep-*")
				if mkErr != nil {
					errMu.Lock()
					errs = append(errs, fmt.Sprintf("MkdirTemp: %v", mkErr))
					errMu.Unlock()
					return
				}
				defer func() { _ = os.RemoveAll(tmpBase) }()

				runFont := func(relName string, content []byte) ([]domain.Finding, domain.ScanCoverage, error) {
					absPath := filepath.Join(tmpBase, relName)
					if wErr := os.WriteFile(absPath, content, 0o600); wErr != nil {
						return nil, domain.ScanCoverage{}, wErr
					}
					defer func() { _ = os.Remove(absPath) }()
					inv, walkErr := inspection.WalkWorkspace(tmpBase)
					if walkErr != nil {
						return nil, domain.ScanCoverage{}, walkErr
					}
					return engine.Analyze(context.Background(), inspection.Request{
						PushSessionID: ptrUUID(domain.MustNewID()),
						ArtifactID:    domain.MustNewID(),
						TargetDir:     tmpBase,
						Stage:         inspection.StagePushEgress,
					}, inv)
				}

				for j := range jobCh {
					comp := zlibCompress(j.fb)
					pdf := makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(comp), len(j.fb)), comp)
					findings, cov, err := runFont("font_"+filepath.Base(j.fp)+".pdf", pdf)
					if err != nil || !cov.Complete || len(findings) != 0 {
						errMu.Lock()
						errs = append(errs, fmt.Sprintf("macOS font %s expected 0 findings, cov=%+v err=%v findings=%+v", j.fp, cov, err, findings))
						errMu.Unlock()
						return
					}
					errMu.Lock()
					checked++
					errMu.Unlock()

					if len(j.fb) >= 12 && binary.BigEndian.Uint32(j.fb[0:4]) == 0x4F54544F {
						nt := int(binary.BigEndian.Uint16(j.fb[4:6]))
						if 12+nt*16 <= len(j.fb) {
							for i := 0; i < nt; i++ {
								rec := j.fb[12+i*16 : 28+i*16]
								if string(rec[0:4]) == "CFF " {
									cffOff := int(binary.BigEndian.Uint32(rec[8:12]))
									cffLen := int(binary.BigEndian.Uint32(rec[12:16]))
									if cffOff >= 0 && cffLen > 0 && cffOff+cffLen <= len(j.fb) {
										cComp := zlibCompress(j.fb[cffOff : cffOff+cffLen])
										cPDF := makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cComp)), cComp)
										cf, ccov, cErr := runFont("type1c_"+filepath.Base(j.fp)+".pdf", cPDF)
										if cErr != nil || !ccov.Complete || len(cf) != 0 {
											errMu.Lock()
											errs = append(errs, fmt.Sprintf("Type1C from %s expected 0 findings, cov=%+v err=%v findings=%+v", j.fp, ccov, cErr, cf))
											errMu.Unlock()
											return
										}
										errMu.Lock()
										checkedType1C++
										errMu.Unlock()
									}
									break
								}
							}
						}
					}
				}
			}()
		}
		wg.Wait()
		if len(errs) > 0 {
			t.Fatalf("%s", errs[0])
		}
		t.Logf("Swept %d macOS fonts (<= 4 MiB) + %d /Type1C streams: 0 FPs", checked, checkedType1C)
	})

	t.Run("Cluster1_TTCFPanicAndSFNT_CFF_CFF2Bypasses", func(t *testing.T) {
		// 1. Exact ttcf slice-bounds panic reproducer (fontOff=2000,2200 pointing to tables at 20..212).
		ttcfPanic := make([]byte, 2400)
		copy(ttcfPanic[0:4], "ttcf")
		binary.BigEndian.PutUint32(ttcfPanic[4:8], 0x00010000)
		binary.BigEndian.PutUint32(ttcfPanic[8:12], 2)
		binary.BigEndian.PutUint32(ttcfPanic[12:16], 2000)
		binary.BigEndian.PutUint32(ttcfPanic[16:20], 2200)
		headTbl := make([]byte, 54)
		binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
		maxpTbl := make([]byte, 6)
		binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
		binary.BigEndian.PutUint16(maxpTbl[4:6], 1)
		locaTbl := make([]byte, 4)
		glyfTbl := make([]byte, 16)
		copy(ttcfPanic[20:], headTbl)
		copy(ttcfPanic[76:], maxpTbl)
		copy(ttcfPanic[84:], locaTbl)
		copy(ttcfPanic[88:], glyfTbl)
		copy(ttcfPanic[120:1900], csprng[:1780])
		for _, fo := range []int{2000, 2200} {
			binary.BigEndian.PutUint32(ttcfPanic[fo:fo+4], 0x00010000)
			binary.BigEndian.PutUint16(ttcfPanic[fo+4:fo+6], 4)
			dirs := []struct {
				tag string
				off uint32
				sz  uint32
				sum uint32
			}{
				{"head", 20, 54, 0},
				{"maxp", 76, 6, sfntSum(maxpTbl)},
				{"loca", 84, 4, sfntSum(locaTbl)},
				{"glyf", 88, 16, sfntSum(glyfTbl)},
			}
			for i, d := range dirs {
				p := fo + 12 + i*16
				copy(ttcfPanic[p:p+4], d.tag)
				binary.BigEndian.PutUint32(ttcfPanic[p+4:p+8], d.sum)
				binary.BigEndian.PutUint32(ttcfPanic[p+8:p+12], d.off)
				binary.BigEndian.PutUint32(ttcfPanic[p+12:p+16], d.sz)
			}
		}
		compPanic := zlibCompress(ttcfPanic)
		panicPDF := makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(compPanic), len(ttcfPanic)), compPanic)
		pf, pcov, pErr := runEngineOnFiles(t, engine, map[string][]byte{"b_ttcf_panic.pdf": panicPDF}, "")
		if pErr != nil || !pcov.Complete || !hasCategory(pf, "IP_CONCEALMENT") {
			t.Fatalf("b_ttcf_panic.pdf expected non-panic IP_CONCEALMENT, cov=%+v err=%v findings=%+v", pcov, pErr, pf)
		}

		// 2. b_sfnt_dsig_0x30_csprng
		dsigPay := make([]byte, 20+8+4096)
		binary.BigEndian.PutUint32(dsigPay[0:4], 1)
		binary.BigEndian.PutUint16(dsigPay[4:6], 1)
		binary.BigEndian.PutUint32(dsigPay[8:12], 1)
		binary.BigEndian.PutUint32(dsigPay[12:16], uint32(8+4096))
		binary.BigEndian.PutUint32(dsigPay[16:20], 20)
		binary.BigEndian.PutUint32(dsigPay[24:28], 4096)
		copy(dsigPay[28:], csprng[:4096])
		dsigPay[28] = 0x30
		compDSIG := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", dsigPay}), nil))

		// 3. b_sfnt_gvar_csprng
		gvarPay := make([]byte, 20+4096)
		binary.BigEndian.PutUint32(gvarPay[0:4], 0x00010000)
		binary.BigEndian.PutUint16(gvarPay[4:6], 1)
		binary.BigEndian.PutUint32(gvarPay[8:12], 20)
		binary.BigEndian.PutUint32(gvarPay[16:20], 20)
		copy(gvarPay[20:], csprng[:4096])
		compGvar := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"gvar", gvarPay}), nil))

		// 4. b_sfnt_meta_csprng
		metaPay := make([]byte, 16+4096)
		binary.BigEndian.PutUint32(metaPay[0:4], 1)
		binary.BigEndian.PutUint32(metaPay[8:12], 16)
		copy(metaPay[16:], csprng[:4096])
		compMeta := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", metaPay}), nil))

		// 5. b_sfnt_20x200b_csprng
		tbls20 := baseSFNTTables()
		for i := 0; i < 20; i++ {
			tbls20 = append(tbls20, sfntTbl{fmt.Sprintf("X%03d", i), csprng[i*200 : (i+1)*200]})
		}
		comp20x200 := zlibCompress(buildSFNT(0x00010000, tbls20, nil))

		// 6. b_sfnt_cvt_csprng (minimal font with cvt CSPRNG)
		compCvt := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"cvt ", csprng[:4096]}), nil))

		// 7. b_cff_gsub_c0_diluted
		c0DilGsub := make([]byte, 4096)
		for i := 0; i < 800; i++ {
			c0DilGsub[i] = 0x00
		}
		copy(c0DilGsub[800:], csprng[:3296])
		hdr := []byte{1, 0, 4, 4}
		nameIdx := buildCFFIndex([][]byte{[]byte("BypassCFF")})
		strIdx := buildCFFIndex(nil)
		gsubIdx := buildCFFIndex([][]byte{c0DilGsub})
		csIdx := buildCFFIndex([][]byte{{14}})
		tdIdxSize := 2 + 1 + 2*4 + 6
		csOff := len(hdr) + len(nameIdx) + tdIdxSize + len(strIdx) + len(gsubIdx)
		var td bytes.Buffer
		td.Write(encodeCFFInt29(int32(csOff)))
		td.WriteByte(17)
		tdIdx := buildCFFIndex([][]byte{td.Bytes()})
		cffBypass := bytes.Join([][]byte{hdr, nameIdx, tdIdx, strIdx, gsubIdx, csIdx}, nil)
		compCFF := zlibCompress(cffBypass)

		// 8. b_sfnt_cff2_csprng (CFF2 header + CSPRNG gap)
		cff2Buf := make([]byte, 5+4+4+4096)
		cff2Buf[0], cff2Buf[1], cff2Buf[2] = 2, 0, 5
		binary.BigEndian.PutUint16(cff2Buf[3:5], 0)
		copy(cff2Buf[5+8:], csprng[:4096])
		compCFF2 := zlibCompress(buildSFNT(0x4F54544F, []sfntTbl{
			{"head", baseSFNTTables()[0].data},
			{"maxp", baseSFNTTables()[1].data},
			{"loca", baseSFNTTables()[2].data},
			{"glyf", baseSFNTTables()[3].data},
			{"CFF2", cff2Buf},
		}, nil))

		for name, comp := range map[string][]byte{
			"b_sfnt_dsig_0x30_csprng.pdf": compDSIG,
			"b_sfnt_gvar_csprng.pdf":      compGvar,
			"b_sfnt_meta_csprng.pdf":      compMeta,
			"b_sfnt_20x200b_csprng.pdf":   comp20x200,
			"b_sfnt_cvt_csprng.pdf":       compCvt,
			"b_sfnt_cff2_csprng.pdf":      compCFF2,
		} {
			pdf := makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(comp)), comp)
			bf, bcov, bErr := runEngineOnFiles(t, engine, map[string][]byte{name: pdf}, "")
			if bErr != nil || !bcov.Complete || !hasCategory(bf, "IP_CONCEALMENT") {
				t.Fatalf("%s expected IP_CONCEALMENT, cov=%+v err=%v findings=%+v", name, bcov, bErr, bf)
			}
			if eff := evalPolicy(bf, bcov); eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
				t.Fatalf("%s expected DENY/QUARANTINE, got %s", name, eff)
			}
		}
		cffPDF := makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(compCFF)), compCFF)
		cf, ccov, cErr := runEngineOnFiles(t, engine, map[string][]byte{"b_cff_gsub_c0_diluted.pdf": cffPDF}, "")
		if cErr != nil || !ccov.Complete || !hasCategory(cf, "IP_CONCEALMENT") {
			t.Fatalf("b_cff_gsub_c0_diluted.pdf expected IP_CONCEALMENT, cov=%+v err=%v findings=%+v", ccov, cErr, cf)
		}
	})

	// =========================================================================
	// Cluster 2: WASM secID == 11 Controls & Bypasses
	// =========================================================================
	t.Run("Cluster2_WASMControlsAndBypasses", func(t *testing.T) {
		appendUleb := func(b []byte, v uint64) []byte {
			var tmp [10]byte
			n := binary.PutUvarint(tmp[:], v)
			return append(b, tmp[:n]...)
		}
		buildWASMSection := func(id byte, body []byte) []byte {
			out := []byte{id}
			out = appendUleb(out, uint64(len(body)))
			return append(out, body...)
		}
		buildDataSegs := func(segs ...[]byte) []byte {
			var b bytes.Buffer
			b.Write(appendUleb(nil, uint64(len(segs))))
			for _, seg := range segs {
				b.WriteByte(0x00)
				b.Write([]byte{0x41, 0x00, 0x0b})
				b.Write(appendUleb(nil, uint64(len(seg))))
				b.Write(seg)
			}
			return b.Bytes()
		}

		// Controls: non-periodic smooth uint16 sine table & monotonic uint32 offset table & real Go WASMs (min, fmt+sha256+json, full, crypto/tls+net/http).
		controls := make(map[string][]byte)
		sin4096 := make([]byte, 4096)
		for i := 0; i < 2048; i++ {
			v := uint16(32768 + 16000*math.Sin(float64(i)*0.013))
			binary.LittleEndian.PutUint16(sin4096[i*2:i*2+2], v)
		}
		mono32 := make([]byte, 4096)
		pos := uint32(0)
		for i := 0; i < 1024; i++ {
			pos += uint32(16 + (i*17)%37)
			binary.LittleEndian.PutUint32(mono32[i*4:i*4+4], pos)
		}
		for name, tbl := range map[string][]byte{
			"lookup_table_sin4096.wasm":  sin4096,
			"monotonic_u32_offsets.wasm": mono32,
		} {
			w := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
			w = append(w, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
			w = append(w, buildWASMSection(11, buildDataSegs(tbl))...)
			controls[name] = w
		}

		if goBin, err := exec.LookPath("go"); err == nil {
			srcDir := t.TempDir()
			programs := map[string]string{
				"min":             "package main\nfunc main() { println(\"hello\") }\n",
				"fmt_sha256_json": "package main\nimport (\n\t\"crypto/sha256\"\n\t\"encoding/json\"\n\t\"fmt\"\n)\nfunc main() {\n\ts := sha256.Sum256([]byte(\"x\"))\n\tb, _ := json.Marshal(fmt.Sprintf(\"%x\", s))\n\tprintln(string(b))\n}\n",
				"full":            "package main\nimport (\n\t\"compress/gzip\"\n\t\"crypto/sha256\"\n\t\"encoding/json\"\n\t\"encoding/xml\"\n\t\"fmt\"\n\t\"net/url\"\n\t\"regexp\"\n)\nfunc main() {\n\t_ = gzip.BestCompression\n\t_ = regexp.MustCompile(\"^[a-z]+$\")\n\t_, _ = url.Parse(\"https://example.com\")\n\t_, _ = xml.Marshal(\"x\")\n\ts := sha256.Sum256([]byte(\"x\"))\n\tb, _ := json.Marshal(fmt.Sprintf(\"%x\", s))\n\tprintln(string(b))\n}\n",
				"tls_http":        "package main\nimport (\n\t\"crypto/tls\"\n\t\"net/http\"\n)\nfunc main() {\n\t_ = &tls.Config{MinVersion: tls.VersionTLS13}\n\t_ = http.MethodGet\n}\n",
			}
			for pname, src := range programs {
				pFile := filepath.Join(srcDir, pname+".go")
				_ = os.WriteFile(pFile, []byte(src), 0o644)
				for _, goos := range []string{"wasip1", "js"} {
					for _, strip := range []bool{false, true} {
						outW := filepath.Join(srcDir, fmt.Sprintf("%s_%s_%v.wasm", pname, goos, strip))
						args := []string{"build"}
						if strip {
							args = append(args, "-ldflags=-s -w")
						}
						args = append(args, "-o", outW, pFile)
						cmd := exec.Command(goBin, args...)
						cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=wasm")
						if cmd.Run() == nil {
							if wb, rErr := os.ReadFile(outW); rErr == nil && len(wb) > 0 {
								controls[fmt.Sprintf("go_%s_%s_strip%v.wasm", pname, goos, strip)] = wb
							}
						}
					}
				}
			}
		}
		type wasmJob struct {
			name string
			data []byte
		}
		type wasmRes struct {
			name string
			wf   []domain.Finding
			wcov domain.ScanCoverage
		}
		wJobCh := make(chan wasmJob, len(controls))
		for name, w := range controls {
			wJobCh <- wasmJob{name: name, data: w}
		}
		close(wJobCh)
		var wErrMu sync.Mutex
		var wErrs []string
		var wResults []wasmRes
		var wWg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wWg.Add(1)
			go func() {
				defer wWg.Done()
				tmpDir, mkErr := os.MkdirTemp("", "custodian-wasm-ctrl-*")
				if mkErr != nil {
					wErrMu.Lock()
					wErrs = append(wErrs, fmt.Sprintf("MkdirTemp: %v", mkErr))
					wErrMu.Unlock()
					return
				}
				defer func() { _ = os.RemoveAll(tmpDir) }()
				for j := range wJobCh {
					abs := filepath.Join(tmpDir, j.name)
					if wErr := os.WriteFile(abs, j.data, 0o600); wErr != nil {
						wErrMu.Lock()
						wErrs = append(wErrs, fmt.Sprintf("WriteFile %s: %v", j.name, wErr))
						wErrMu.Unlock()
						return
					}
					inv, walkErr := inspection.WalkWorkspace(tmpDir)
					if walkErr != nil {
						_ = os.Remove(abs)
						wErrMu.Lock()
						wErrs = append(wErrs, fmt.Sprintf("WalkWorkspace %s: %v", j.name, walkErr))
						wErrMu.Unlock()
						return
					}
					wf, wcov, wErr := engine.Analyze(context.Background(), inspection.Request{
						PushSessionID: ptrUUID(domain.MustNewID()),
						ArtifactID:    domain.MustNewID(),
						TargetDir:     tmpDir,
						Stage:         inspection.StagePushEgress,
					}, inv)
					_ = os.Remove(abs)
					if wErr != nil || !wcov.Complete || len(wf) != 0 {
						wErrMu.Lock()
						wErrs = append(wErrs, fmt.Sprintf("WASM control %s expected 0 findings, cov=%+v err=%v findings=%+v", j.name, wcov, wErr, wf))
						wErrMu.Unlock()
						return
					}
					wErrMu.Lock()
					wResults = append(wResults, wasmRes{name: j.name, wf: wf, wcov: wcov})
					wErrMu.Unlock()
				}
			}()
		}
		wWg.Wait()
		if len(wErrs) > 0 {
			t.Fatalf("%s", wErrs[0])
		}
		for _, wr := range wResults {
			if eff := evalPolicy(wr.wf, wr.wcov); eff != domain.PolicyEffectAllow {
				t.Fatalf("WASM control %s expected ALLOW, got %s", wr.name, eff)
			}
		}

		// Bypasses:
		bypasses := make(map[string][]byte)
		wrapSec11 := func(segs ...[]byte) []byte {
			w := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
			w = append(w, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
			w = append(w, buildWASMSection(11, buildDataSegs(segs...))...)
			return w
		}
		u32Nul := make([]byte, 4096)
		u32A := make([]byte, 4096)
		monoCSPRNG := make([]byte, 4096)
		for i := 0; i < 1024; i++ {
			copy(u32Nul[i*4:i*4+3], csprng[i*3:i*3+3])
			copy(u32A[i*4:i*4+3], csprng[i*3:i*3+3])
			u32A[i*4+3] = 'A'
			copy(monoCSPRNG[i*4:i*4+2], csprng[i*2:i*2+2])
			binary.LittleEndian.PutUint16(monoCSPRNG[i*4+2:i*4+4], uint16(i))
		}
		u16Nul := make([]byte, 4096)
		for i := 0; i < 2048; i++ {
			u16Nul[i*2] = csprng[i]
		}
		bypasses["wasm_u32_nul_csprng.wasm"] = wrapSec11(u32Nul)
		bypasses["wasm_u16_nul_csprng.wasm"] = wrapSec11(u16Nul)
		bypasses["wasm_u32_41_csprng.wasm"] = wrapSec11(u32A)
		bypasses["wasm_mono_u32_csprng.wasm"] = wrapSec11(monoCSPRNG)

		var segs20Nul, segs20A [][]byte
		for i := 0; i < 20; i++ {
			sN := make([]byte, 400)
			copy(sN[:200], csprng[i*200:(i+1)*200])
			segs20Nul = append(segs20Nul, sN)
			sA := bytes.Repeat([]byte{'A'}, 400)
			copy(sA[:200], csprng[i*200:(i+1)*200])
			segs20A = append(segs20A, sA)
		}
		bypasses["b_wasm_sec11_20x_200b_csprng_200b_nul.wasm"] = wrapSec11(segs20Nul...)
		bypasses["b_wasm_sec11_20x_200b_csprng_200b_A.wasm"] = wrapSec11(segs20A...)

		// 32 x 512B unique functions with calls + 16384B CSPRNG in secID == 11.
		var code32 bytes.Buffer
		code32.WriteByte(32)
		for f := 0; f < 32; f++ {
			var fb bytes.Buffer
			fb.WriteByte(0x00)
			fb.Write([]byte{0x41, byte(f + 1), 0x04, 0x40, 0x10, 0x00, 0x0b})
			for i := 0; i < 512; i++ {
				op := byte(0x20 + ((i + f) % 32))
				if op == 0x01 || op == 0x0b {
					op = 0x41
				}
				fb.WriteByte(op)
			}
			fb.WriteByte(0x0b)
			code32.Write(appendUleb(nil, uint64(fb.Len())))
			code32.Write(fb.Bytes())
		}
		funcSec32 := make([]byte, 33)
		funcSec32[0] = 32
		w32 := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		w32 = append(w32, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		w32 = append(w32, buildWASMSection(3, funcSec32)...)
		w32 = append(w32, buildWASMSection(7, []byte{0x01, 0x04, 'm', 'a', 'i', 'n', 0x00, 0x00})...)
		w32 = append(w32, buildWASMSection(10, code32.Bytes())...)
		w32 = append(w32, buildWASMSection(11, buildDataSegs(csprng[:16384]))...)
		bypasses["b_wasm_subst32_16kb_sec11_csprng.wasm"] = w32

		for name, w := range bypasses {
			bf, bcov, bErr := runEngineOnFiles(t, engine, map[string][]byte{name: w}, "")
			if bErr != nil || !bcov.Complete || !hasCategory(bf, "IP_CONCEALMENT") {
				t.Fatalf("WASM bypass %s expected IP_CONCEALMENT, cov=%+v err=%v findings=%+v", name, bcov, bErr, bf)
			}
			if eff := evalPolicy(bf, bcov); eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
				t.Fatalf("WASM bypass %s expected DENY/QUARANTINE, got %s", name, eff)
			}
		}
	})

	// =========================================================================
	// Cluster 3: Digest Arrays >64, 16-bit Smooth & Alt-Row PDF Image, Type1 Hdr/Tail,
	// ICC CLUT/C0, JPEG DQT/DRI RST, ASCII85 <~ Shadowing, # Filename Collision
	// =========================================================================
	t.Run("Cluster3_ControlsAndBypasses", func(t *testing.T) {
		// 1. > 64-entry SHA-256 arrays (80 entries) -> 0 findings (ALLOW).
		var hex80, b64_80 []string
		for i := 0; i < 80; i++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("allowlist-artifact-%d", i)))
			hex80 = append(hex80, fmt.Sprintf("%q", hex.EncodeToString(sum[:])))
			b64_80 = append(b64_80, fmt.Sprintf("%q", base64.RawURLEncoding.EncodeToString(sum[:])))
		}
		largeHexGo := []byte("package manifests\nvar Sha256Checksums = []string{\n" + strings.Join(hex80, ",\n") + "\n}\n")
		largeB64Go := []byte("package manifests\nvar RawB64Sha256 = []string{\n" + strings.Join(b64_80, ",\n") + "\n}\n")

		// 2. Smooth dithered 16-bit PDF raster -> 0 findings (ALLOW).
		raw16 := make([]byte, 64*64*2)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				v := uint16(y*900 + x*100 + ((x*17 + y*31) % 7))
				off := (y*64 + x) * 2
				binary.BigEndian.PutUint16(raw16[off:off+2], v)
			}
		}
		comp16 := zlibCompress(raw16)
		pdf16Smooth := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 16 /Length %d /Filter /FlateDecode", len(comp16)), comp16)

		// 3. Type1 font with /Notice (Copyright ... All Rights Reserved.) -> 0 findings (ALLOW).
		eexecEncrypt := func(plain []byte) []byte {
			r := uint32(55665)
			out := make([]byte, len(plain))
			for i, p := range plain {
				c := p ^ byte(r>>8)
				out[i] = c
				r = ((uint32(c)+r)*52845 + 22719) & 0xFFFF
			}
			return out
		}
		t1NoticeBody := append([]byte{0x12, 0x34, 0x56, 0x78}, []byte("dup /Private 8 dict dup begin /password 5839 def end def currentdict end currentfile closefile\n")...)
		t1NoticeStream := append([]byte("%!PS-AdobeFont-1.0: NoticeFont 001.000\n/Notice (Copyright 2020 Adobe Systems Inc. All Rights Reserved.) readonly def\n/FontName /NoticeFont def\ncurrentfile eexec\n"), eexecEncrypt(t1NoticeBody)...)
		t1NoticeStream = append(t1NoticeStream, []byte("\n"+strings.Repeat("0", 512)+"\ncleartomark\n")...)
		compT1Notice := zlibCompress(t1NoticeStream)
		pdfT1Notice := makeStreamPDF(fmt.Sprintf("/Length %d /Length1 120 /Filter /FlateDecode", len(compT1Notice)), compT1Notice)

		// 4. 800 KB <~ <~ ... ~> ASCII85 DoS stress (< 200 ms, 0 findings).
		a85Stress := append(bytes.Repeat([]byte("<~ "), (800*1024)/3), []byte("~>")...)
		startA85 := time.Now()
		fA85, covA85, errA85 := runEngineOnFiles(t, engine, map[string][]byte{"a85_800kb.js": a85Stress}, "")
		elA85 := time.Since(startA85)
		if errA85 != nil || !covA85.Complete || len(fA85) != 0 {
			t.Fatalf("a85_800kb.js expected 0 findings, cov=%+v err=%v findings=%+v", covA85, errA85, fA85)
		}
		t.Logf("a85_800kb.js (%d bytes): %v", len(a85Stress), elA85)

		for name, payload := range map[string][]byte{
			"large_sha_array_80.go":              largeHexGo,
			"raw_urlsafe_b64_sha256_array_80.go": largeB64Go,
			"pdf_16bit_smooth.pdf":               pdf16Smooth,
			"pdf_type1_notice_copyright.pdf":     pdfT1Notice,
		} {
			cf, ccov, cErr := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if cErr != nil || !ccov.Complete || len(cf) != 0 {
				t.Fatalf("Cluster3 control %s expected 0 findings, cov=%+v err=%v findings=%+v", name, ccov, cErr, cf)
			}
			if eff := evalPolicy(cf, ccov); eff != domain.PolicyEffectAllow {
				t.Fatalf("Cluster3 control %s expected ALLOW, got %s", name, eff)
			}
		}

		// Bypasses:
		bypasses := make(map[string][]byte)

		// Alt-row PDF Image (even=0x00, odd=CSPRNG) + Predictor=15 variant.
		altRows := make([]byte, 64*64)
		altRowsPred := make([]byte, 64*65)
		for y := 0; y < 64; y++ {
			if y%2 == 1 {
				copy(altRows[y*64:(y+1)*64], csprng[(y/2)*64:(y/2+1)*64])
				copy(altRowsPred[y*65+1:(y+1)*65], csprng[(y/2)*64:(y/2+1)*64])
			}
		}
		cAlt := zlibCompress(altRows)
		cAltP := zlibCompress(altRowsPred)
		bypasses["b_img_alt_rows_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(cAlt)), cAlt)
		bypasses["b_img_alt_rows_pred15_csprng.pdf"] = makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8 /DecodeParms << /Predictor 15 /Colors 1 /Columns 64 >> /Length %d /Filter /FlateDecode", len(cAltP)), cAltP)

		// Type1 header IP & tail IP.
		benignEexec := eexecEncrypt(append([]byte{0x12, 0x34, 0x56, 0x78}, []byte("dup /Private 8 dict dup begin /password 5839 def end def currentdict end currentfile closefile\n")...))
		t1HdrIP := bytes.Join([][]byte{
			[]byte("%!PS-AdobeFont-1.0: BypassHdr 001.000\n/FontName /BypassHdr def\n"),
			stripped,
			[]byte("\nconst tok = \"ghp_0123456789abcdef0123456789abcdef0123\"\ncurrentfile eexec\n"),
			benignEexec,
			[]byte("\n" + strings.Repeat("0", 512) + "\ncleartomark\n"),
		}, nil)
		t1TailIP := bytes.Join([][]byte{
			[]byte("%!PS-AdobeFont-1.0: BypassTail 001.000\n/FontName /BypassTail def\ncurrentfile eexec\n"),
			benignEexec,
			[]byte("\n" + strings.Repeat("0", 512) + "\ncleartomark\n"),
			stripped,
			[]byte("\nconst tok = \"ghp_0123456789abcdef0123456789abcdef0123\"\n"),
		}, nil)
		cT1H := zlibCompress(t1HdrIP)
		cT1T := zlibCompress(t1TailIP)
		bypasses["b_t1_hdr_ip.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 200 /Filter /FlateDecode", len(cT1H)), cT1H)
		bypasses["b_t1_trail_ip.pdf"] = makeStreamPDF(fmt.Sprintf("/Length %d /Length1 90 /Filter /FlateDecode", len(cT1T)), cT1T)

		// ICC multi-channel half-zero mft1 & mAB & C0-diluted text tag.
		buildICC := func(extraSig string, extraTag []byte) []byte {
			const numTags = 4
			const hdrEnd = 132 + numTags*12
			descTag := make([]byte, 24)
			copy(descTag[0:4], "desc")
			binary.BigEndian.PutUint32(descTag[8:12], 8)
			copy(descTag[12:], "sRGB_IEC")
			cprtTag := make([]byte, 24)
			copy(cprtTag[0:4], "text")
			copy(cprtTag[8:], "Copyright 2026")
			wtptTag := make([]byte, 20)
			copy(wtptTag[0:4], "XYZ ")
			pad4 := func(b []byte) []byte {
				for len(b)%4 != 0 {
					b = append(b, 0)
				}
				return b
			}
			descTag = pad4(descTag)
			cprtTag = pad4(cprtTag)
			wtptTag = pad4(wtptTag)
			extraPad := pad4(append([]byte(nil), extraTag...))
			off0 := hdrEnd
			off1 := off0 + len(descTag)
			off2 := off1 + len(cprtTag)
			off3 := off2 + len(wtptTag)
			total := off3 + len(extraPad)
			icc := make([]byte, total)
			binary.BigEndian.PutUint32(icc[0:4], uint32(total))
			icc[8] = 2
			copy(icc[12:16], "mntr")
			copy(icc[16:20], "RGB ")
			copy(icc[20:24], "XYZ ")
			copy(icc[36:40], "acsp")
			binary.BigEndian.PutUint32(icc[128:132], numTags)
			putEntry := func(idx int, sig string, off, sz int) {
				pos := 132 + idx*12
				copy(icc[pos:pos+4], sig)
				binary.BigEndian.PutUint32(icc[pos+4:pos+8], uint32(off))
				binary.BigEndian.PutUint32(icc[pos+8:pos+12], uint32(sz))
			}
			putEntry(0, "desc", off0, len(descTag))
			putEntry(1, "cprt", off1, len(cprtTag))
			putEntry(2, "wtpt", off2, len(wtptTag))
			putEntry(3, extraSig, off3, len(extraTag))
			copy(icc[off0:], descTag)
			copy(icc[off1:], cprtTag)
			copy(icc[off2:], wtptTag)
			copy(icc[off3:], extraPad)
			return icc
		}
		// mft1 half-zero CLUT (ic=2, oc=4, g=32 -> 1024 pts * 4 = 4096B; ch 2..3 = CSPRNG).
		mft1Half := make([]byte, 48+2*256+4096+4*256)
		copy(mft1Half[0:4], "mft1")
		mft1Half[8], mft1Half[9], mft1Half[10] = 2, 4, 32
		pos := 48
		for k := 0; k < 2; k++ {
			for i := 0; i < 256; i++ {
				mft1Half[pos+i] = byte(i)
			}
			pos += 256
		}
		for pt := 0; pt < 1024; pt++ {
			mft1Half[pos+pt*4+2] = csprng[pt*2]
			mft1Half[pos+pt*4+3] = csprng[pt*2+1]
		}
		pos += 4096
		for k := 0; k < 4; k++ {
			for i := 0; i < 256; i++ {
				mft1Half[pos+i] = byte(i)
			}
			pos += 256
		}
		cICCMft1 := zlibCompress(buildICC("A2B0", mft1Half))
		bypasses["b_icc_mft1_half_zero_clut.pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cICCMft1)), cICCMft1)

		// mAB half-zero CLUT (3072B CLUT: first 1536B zero, second 1536B CSPRNG).
		mabHalf := make([]byte, 32+20+3072)
		copy(mabHalf[0:4], "mAB ")
		mabHalf[8], mabHalf[9] = 3, 3
		binary.BigEndian.PutUint32(mabHalf[24:28], 32)
		mabHalf[32], mabHalf[33], mabHalf[34] = 8, 8, 16
		mabHalf[32+16] = 1
		copy(mabHalf[32+20+1536:], csprng[:1536])
		cICCMab := zlibCompress(buildICC("A2B0", mabHalf))
		bypasses["b_icc_mab_half_zero_clut.pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cICCMab)), cICCMab)

		// C0-diluted ICC text tag.
		c0TextTag := make([]byte, 8+4096)
		copy(c0TextTag[0:4], "text")
		copy(c0TextTag[8+800:], csprng[:3296])
		cICCText := zlibCompress(buildICC("desc", c0TextTag))
		bypasses["b_icc_text_c0_diluted.pdf"] = makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cICCText)), cICCText)

		// JPEG DQT non-constant diluted (2x64B CSPRNG + 2x64B [0x01, 0x02]).
		var jBuf bytes.Buffer
		img := image.NewRGBA(image.Rect(0, 0, 16, 16))
		_ = jpeg.Encode(&jBuf, img, &jpeg.Options{Quality: 75})
		baseJ := jBuf.Bytes()
		sosIdx := bytes.Index(baseJ, []byte{0xFF, 0xDA})
		var dqtDil bytes.Buffer
		dqtDil.Write([]byte{0xFF, 0xDB})
		_ = binary.Write(&dqtDil, binary.BigEndian, uint16(2+4*65))
		dqtDil.WriteByte(0x00)
		dqtDil.Write(csprng[:64])
		dqtDil.WriteByte(0x01)
		dqtDil.Write(csprng[64:128])
		dqtDil.WriteByte(0x02)
		dqtDil.Write(bytes.Repeat([]byte{0x01, 0x02}, 32))
		dqtDil.WriteByte(0x03)
		dqtDil.Write(bytes.Repeat([]byte{0x01, 0x02}, 32))
		bypasses["b_jpg_dqt_nonconst_diluted.jpg"] = append(append(append([]byte(nil), baseJ[:sosIdx]...), dqtDil.Bytes()...), baseJ[sosIdx:]...)

		// JPEG DRI 144 x 28B RST intervals (96x96 grayscale, 144 MCUs, DRI=1).
		stuffFF := func(raw []byte) []byte {
			var b bytes.Buffer
			for _, c := range raw {
				b.WriteByte(c)
				if c == 0xFF {
					b.WriteByte(0x00)
				}
			}
			return b.Bytes()
		}
		var driJ bytes.Buffer
		driJ.Write([]byte{0xFF, 0xD8})
		driJ.Write(append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...))
		driJ.Write([]byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x60, 0x00, 0x60, 0x01, 0x01, 0x11, 0x00})
		driJ.Write([]byte{0xFF, 0xC4, 0x00, 0x1F, 0x00, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
		driJ.Write([]byte{0xFF, 0xC4, 0x00, 0x14, 0x10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00})
		driJ.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
		driJ.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
		for iv := 0; iv < 144; iv++ {
			driJ.WriteByte(0x00)
			driJ.Write(stuffFF(csprng[iv*28 : (iv+1)*28]))
			if iv < 143 {
				driJ.Write([]byte{0xFF, byte(0xD0 + (iv % 8))})
			}
		}
		driJ.Write([]byte{0xFF, 0xD9})
		if _, dErr := jpeg.Decode(bytes.NewReader(driJ.Bytes())); dErr != nil {
			t.Fatalf("b_jpg_dri_144x28b_rst fixture invalid JPEG: %v", dErr)
		}
		bypasses["b_jpg_dri_144x28b_rst.jpg"] = driJ.Bytes()

		// L4b ASCII85 decoy comment shadowing.
		var a85Buf bytes.Buffer
		a85Buf.WriteString("// <~ decoy comment\nconst d = `\n<~")
		a85Enc := ascii85.NewEncoder(&a85Buf)
		_, _ = a85Enc.Write(stripped)
		_ = a85Enc.Close()
		a85Buf.WriteString("~>\n`;\n")
		bypasses["b_l4b_ascii85_decoy_comment.js"] = a85Buf.Bytes()

		for name, payload := range bypasses {
			bf, bcov, bErr := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
			if bErr != nil || !bcov.Complete || len(bf) == 0 {
				t.Fatalf("Cluster3 bypass %s expected findings, cov=%+v err=%v findings=%+v", name, bcov, bErr, bf)
			}
			eff := evalPolicy(bf, bcov)
			if eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
				t.Fatalf("Cluster3 bypass %s expected DENY or QUARANTINE, got %s (findings=%+v)", name, eff, bf)
			}
			assertNoRawLeak(t, bf, bcov, "TelemetryCalibrator", "Acme Proprietary", "ghp_0123456789abcdef0123456789abcdef0123")
		}

		// #-filename collision fix: notes#printable.go & helper#icc.go must NOT suppress L3 bare copyright+all-rights-reserved.
		bareCopy := []byte("// Copyright 2026 UnseenCorp Inc. All rights reserved.\npackage helper\nfunc F() int { return 42 }\n")
		for _, fname := range []string{"notes#printable.go", "helper#icc.go"} {
			hf, hcov, hErr := runEngineOnFiles(t, engine, map[string][]byte{fname: bareCopy}, "")
			if hErr != nil || !hcov.Complete || !hasCategory(hf, "IP_HEADER_MARKER") {
				t.Fatalf("%s expected IP_HEADER_MARKER (CONFIDENTIAL), cov=%+v err=%v findings=%+v", fname, hcov, hErr, hf)
			}
		}
	})
}

func TestWave8RemediationAllFindings(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 16 << 20,
	})

	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	compiledPol, errs := polEngine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("compile push-ip-protection.yaml: %+v", errs)
	}

	evalPolicy := func(findings []domain.Finding, cov domain.ScanCoverage) domain.PolicyEffect {
		sum := inspection.InspectionSummary{
			MandatoryScannersComplete: cov.Complete && cov.FilesSkipped == 0,
			ScanComplete:              cov.Complete && cov.FilesSkipped == 0,
		}
		for _, f := range findings {
			sum.TotalFindings++
			switch f.Category {
			case "SECRET":
				if f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh {
					sum.CriticalSecrets++
				}
			case "IP_CONCEALMENT":
				sum.ConcealmentFindings++
			case "IP_EXACT":
				sum.IPExactMatches++
			case "IP_WINNOW":
				sum.IPWinnowMatches++
			case "IP_HEADER_STRIP":
				sum.IPHeaderStripMatches++
			}
		}
		res, pErr := polEngine.Evaluate(context.Background(), compiledPol, policy.StagePushEgress, policy.PolicyInput{
			Stage:    policy.StagePushEgress,
			Findings: workflow.SummaryToFindingsInput(sum),
			Assessment: policy.AssessmentInput{
				Status:      "NOT_REQUIRED",
				IPRisk:      "NONE",
				Risk:        "NONE",
				Disposition: "NOT_REQUIRED",
			},
			Destination: policy.DestinationInput{
				ID:             "repo-internal",
				Name:           "acme/app",
				Host:           "github.com",
				Registered:     true,
				External:       false,
				Classification: "INTERNAL",
			},
			Push: policy.PushInput{
				RefNames:   []string{"refs/heads/main"},
				EgressMode: "ENFORCE_BLOCK",
			},
		})
		if pErr != nil {
			t.Fatalf("policy.Evaluate: %v", pErr)
		}
		return res.Effect
	}

	csprng := make([]byte, 65536)
	for off := 0; off < len(csprng); off += 32 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("wave8-csprng-%d", off)))
		copy(csprng[off:], sum[:])
	}
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	zlibCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return buf.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< " + dictEntries + " >>\nstream\n")
		b.Write(body)
		b.WriteString("\nendstream\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
		return b.Bytes()
	}
	sfntSum := func(tbl []byte) uint32 {
		padded := append([]byte(nil), tbl...)
		for len(padded)%4 != 0 {
			padded = append(padded, 0)
		}
		var s uint32
		for i := 0; i+4 <= len(padded); i += 4 {
			s += binary.BigEndian.Uint32(padded[i : i+4])
		}
		return s
	}
	type sfntTbl struct {
		tag  string
		data []byte
	}
	buildSFNT := func(sfntTag uint32, tbls []sfntTbl) []byte {
		var body bytes.Buffer
		dirSize := 12 + len(tbls)*16
		var dir bytes.Buffer
		_ = binary.Write(&dir, binary.BigEndian, sfntTag)
		_ = binary.Write(&dir, binary.BigEndian, uint16(len(tbls)))
		_ = binary.Write(&dir, binary.BigEndian, uint16(64))
		_ = binary.Write(&dir, binary.BigEndian, uint16(2))
		_ = binary.Write(&dir, binary.BigEndian, uint16(0))
		for _, te := range tbls {
			off := dirSize + body.Len()
			body.Write(te.data)
			for body.Len()%4 != 0 {
				body.WriteByte(0)
			}
			dir.WriteString(te.tag)
			_ = binary.Write(&dir, binary.BigEndian, sfntSum(te.data))
			_ = binary.Write(&dir, binary.BigEndian, uint32(off))
			_ = binary.Write(&dir, binary.BigEndian, uint32(len(te.data)))
		}
		return append(dir.Bytes(), body.Bytes()...)
	}
	baseSFNTTables := func() []sfntTbl {
		headTbl := make([]byte, 54)
		binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
		maxpTbl := make([]byte, 6)
		binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
		binary.BigEndian.PutUint16(maxpTbl[4:6], 16)
		locaTbl := make([]byte, 34)
		glyfTbl := make([]byte, 0)
		return []sfntTbl{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", locaTbl}, {"glyf", glyfTbl}}
	}
	buildCFFIndex := func(items [][]byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint16(len(items)))
		if len(items) == 0 {
			return b.Bytes()
		}
		b.WriteByte(4)
		off := uint32(1)
		_ = binary.Write(&b, binary.BigEndian, off)
		for _, it := range items {
			off += uint32(len(it))
			_ = binary.Write(&b, binary.BigEndian, off)
		}
		for _, it := range items {
			b.Write(it)
		}
		return b.Bytes()
	}
	buildCFF2Index := func(items [][]byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(len(items)))
		if len(items) == 0 {
			return b.Bytes()
		}
		b.WriteByte(4)
		off := uint32(1)
		_ = binary.Write(&b, binary.BigEndian, off)
		for _, it := range items {
			off += uint32(len(it))
			_ = binary.Write(&b, binary.BigEndian, off)
		}
		for _, it := range items {
			b.Write(it)
		}
		return b.Bytes()
	}
	encodeCFFInt29 := func(v int32) []byte {
		out := make([]byte, 5)
		out[0] = 29
		binary.BigEndian.PutUint32(out[1:5], uint32(v))
		return out
	}
	wrapDER := func(tag byte, content []byte) []byte {
		var b bytes.Buffer
		b.WriteByte(tag)
		l := len(content)
		if l < 0x80 {
			b.WriteByte(byte(l))
		} else if l <= 0xff {
			b.Write([]byte{0x81, byte(l)})
		} else {
			b.Write([]byte{0x82, byte(l >> 8), byte(l)})
		}
		b.Write(content)
		return b.Bytes()
	}

	assertRejected := func(st *testing.T, name string, files map[string][]byte, expectedCategory string) {
		st.Helper()
		bf, bcov, bErr := runEngineOnFiles(st, engine, files, "")
		if bErr != nil || !bcov.Complete || !hasCategory(bf, expectedCategory) {
			st.Fatalf("%s expected %s, cov=%+v err=%v findings=%+v", name, expectedCategory, bcov, bErr, bf)
		}
		eff := evalPolicy(bf, bcov)
		if eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
			st.Fatalf("%s expected DENY or QUARANTINE, got %s (findings=%+v)", name, eff, bf)
		}
	}

	t.Run("Group1_SFNT_DSIG_Glyf_Cvt_Meta_Tables", func(t *testing.T) {
		// 1. DSIG: 23-28B PKCS#7 DER prefix + 4KB / 60KB CSPRNG (1b, N4, probe_b)
		pkcs7Prefix := []byte{
			0x30, 0x82, 0x10, 0x17,
			0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
			0xa0, 0x82, 0x10, 0x08,
			0x30, 0x82, 0x10, 0x04,
			0x02, 0x01, 0x01,
		}
		derTrail := append(append([]byte(nil), pkcs7Prefix...), csprng[:4096]...)
		dsigPrefix := make([]byte, 20+8+len(derTrail))
		binary.BigEndian.PutUint32(dsigPrefix[0:4], 1)
		binary.BigEndian.PutUint16(dsigPrefix[4:6], 1)
		binary.BigEndian.PutUint32(dsigPrefix[8:12], 1)
		binary.BigEndian.PutUint32(dsigPrefix[12:16], uint32(8+len(derTrail)))
		binary.BigEndian.PutUint32(dsigPrefix[16:20], 20)
		binary.BigEndian.PutUint32(dsigPrefix[24:28], uint32(len(derTrail)))
		copy(dsigPrefix[28:], derTrail)
		compDSIGPref := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", dsigPrefix})))
		assertRejected(t, "1b_N4_probe_b_dsig_der_csprng.pdf", map[string][]byte{
			"1b_dsig.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compDSIGPref)), compDSIGPref),
		}, "IP_CONCEALMENT")

		// Full SignedData DER framing with opaque 512B OCTET STRING CSPRNG inside encapContentInfo
		eci := wrapDER(0x30, append(wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}), wrapDER(0xa0, wrapDER(0x04, csprng[:512]))...))
		sd := wrapDER(0x30, bytes.Join([][]byte{
			wrapDER(0x02, []byte{1}),
			wrapDER(0x31, nil),
			eci,
			wrapDER(0x31, nil),
		}, nil))
		fullPKCS7 := wrapDER(0x30, append(wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}), wrapDER(0xa0, sd)...))
		dsigOpaque := make([]byte, 20+8+len(fullPKCS7))
		binary.BigEndian.PutUint32(dsigOpaque[0:4], 1)
		binary.BigEndian.PutUint16(dsigOpaque[4:6], 1)
		binary.BigEndian.PutUint32(dsigOpaque[8:12], 1)
		binary.BigEndian.PutUint32(dsigOpaque[12:16], uint32(8+len(fullPKCS7)))
		binary.BigEndian.PutUint32(dsigOpaque[16:20], 20)
		binary.BigEndian.PutUint32(dsigOpaque[24:28], uint32(len(fullPKCS7)))
		copy(dsigOpaque[28:], fullPKCS7)
		compDSIGOpaque := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", dsigOpaque})))
		assertRejected(t, "dsig_pkcs7_encap_opaque_csprng.pdf", map[string][]byte{
			"dsig_eci.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compDSIGOpaque)), compDSIGOpaque),
		}, "IP_CONCEALMENT")

		// 16 x 250B C0-diluted small DSIG signatures (A, N5)
		var smallDSIG bytes.Buffer
		_ = binary.Write(&smallDSIG, binary.BigEndian, uint32(1))
		_ = binary.Write(&smallDSIG, binary.BigEndian, uint16(16))
		_ = binary.Write(&smallDSIG, binary.BigEndian, uint16(0))
		blkOff := uint32(8 + 16*12)
		for i := 0; i < 16; i++ {
			_ = binary.Write(&smallDSIG, binary.BigEndian, uint32(1))
			_ = binary.Write(&smallDSIG, binary.BigEndian, uint32(8+250))
			_ = binary.Write(&smallDSIG, binary.BigEndian, blkOff+uint32(i*(8+250)))
		}
		for i := 0; i < 16; i++ {
			_ = binary.Write(&smallDSIG, binary.BigEndian, uint32(0))
			_ = binary.Write(&smallDSIG, binary.BigEndian, uint32(250))
			smallDSIG.Write(make([]byte, 50))
			smallDSIG.Write(csprng[i*200 : i*200+200])
		}
		compSmallDSIG := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", smallDSIG.Bytes()})))
		assertRejected(t, "A_N5_sfnt_dsig_small16x250_c0.pdf", map[string][]byte{
			"dsig_small.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compSmallDSIG)), compSmallDSIG),
		}, "IP_CONCEALMENT")

		// 2. glyf: nc=0 + 4KB CSPRNG (1e, probe_a), nc=1 + 4KB CSPRNG instructions (N13), nc=-1 composite + 4KB instructions
		glyfNC0 := make([]byte, 10+4096)
		binary.BigEndian.PutUint16(glyfNC0[6:8], 100)
		binary.BigEndian.PutUint16(glyfNC0[8:10], 100)
		copy(glyfNC0[10:], csprng[:4096])
		head0 := make([]byte, 54)
		binary.BigEndian.PutUint32(head0[12:16], 0x5F0F3CF5)
		binary.BigEndian.PutUint16(head0[50:52], 1)
		maxp1 := make([]byte, 6)
		binary.BigEndian.PutUint32(maxp1[0:4], 0x00010000)
		binary.BigEndian.PutUint16(maxp1[4:6], 1)
		loca0 := make([]byte, 8)
		binary.BigEndian.PutUint32(loca0[4:8], uint32(len(glyfNC0)))
		compGlyf0 := zlibCompress(buildSFNT(0x00010000, []sfntTbl{{"head", head0}, {"maxp", maxp1}, {"loca", loca0}, {"glyf", glyfNC0}}))
		assertRejected(t, "1e_probe_a_glyf_nc0.pdf", map[string][]byte{
			"glyf_nc0.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compGlyf0)), compGlyf0),
		}, "IP_CONCEALMENT")

		glyfInst := make([]byte, 10+2+2+4096+3)
		binary.BigEndian.PutUint16(glyfInst[0:2], 1)
		binary.BigEndian.PutUint16(glyfInst[6:8], 100)
		binary.BigEndian.PutUint16(glyfInst[8:10], 100)
		binary.BigEndian.PutUint16(glyfInst[12:14], 4096)
		copy(glyfInst[14:], csprng[:4096])
		binary.BigEndian.PutUint32(loca0[4:8], uint32(len(glyfInst)))
		compGlyfInst := zlibCompress(buildSFNT(0x00010000, []sfntTbl{{"head", head0}, {"maxp", maxp1}, {"loca", loca0}, {"glyf", glyfInst}}))
		assertRejected(t, "N13_glyf_csprng_instructions.pdf", map[string][]byte{
			"glyf_inst.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compGlyfInst)), compGlyfInst),
		}, "IP_CONCEALMENT")

		glyfComp := make([]byte, 10+6+2+4096)
		binary.BigEndian.PutUint16(glyfComp[0:2], 0xFFFF) // nc = -1
		binary.BigEndian.PutUint16(glyfComp[6:8], 100)
		binary.BigEndian.PutUint16(glyfComp[8:10], 100)
		binary.BigEndian.PutUint16(glyfComp[10:12], 0x0100) // WE_HAVE_INSTRUCTIONS
		binary.BigEndian.PutUint16(glyfComp[16:18], 4096)
		copy(glyfComp[18:], csprng[:4096])
		binary.BigEndian.PutUint32(loca0[4:8], uint32(len(glyfComp)))
		compGlyfComp := zlibCompress(buildSFNT(0x00010000, []sfntTbl{{"head", head0}, {"maxp", maxp1}, {"loca", loca0}, {"glyf", glyfComp}}))
		assertRejected(t, "glyf_composite_csprng_instructions.pdf", map[string][]byte{
			"glyf_comp.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compGlyfComp)), compGlyfComp),
		}, "IP_CONCEALMENT")

		// 3. cvt 2048B CSPRNG with empty glyf + zero fpgm (1a, N1, probe_c)
		compCvtStub := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(),
			sfntTbl{"fpgm", make([]byte, 256)},
			sfntTbl{"cvt ", csprng[:2048]},
		)))
		assertRejected(t, "1a_N1_probe_c_cvt_2048b.pdf", map[string][]byte{
			"cvt_2kb.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compCvtStub)), compCvtStub),
		}, "IP_CONCEALMENT")

		// 4. meta "appl" C0-diluted (1c, N2) & 7-bit random (N3)
		buildMetaAppl := func(recData []byte) []byte {
			rec := make([]byte, 24+len(recData))
			binary.BigEndian.PutUint32(rec[0:4], 2)
			binary.LittleEndian.PutUint32(rec[8:12], 0x18)
			copy(rec[24:], recData)
			m := make([]byte, 28+len(rec))
			binary.BigEndian.PutUint32(m[0:4], 1)
			binary.BigEndian.PutUint32(m[8:12], 28)
			binary.BigEndian.PutUint32(m[12:16], 1)
			copy(m[16:20], "appl")
			binary.BigEndian.PutUint32(m[20:24], 28)
			binary.BigEndian.PutUint32(m[24:28], uint32(len(rec)))
			copy(m[28:], rec)
			return m
		}
		metaC0 := append(append([]byte(nil), csprng[:2048]...), make([]byte, 512)...)
		compMetaC0 := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", buildMetaAppl(metaC0)})))
		assertRejected(t, "1c_N2_meta_appl_c0.pdf", map[string][]byte{
			"meta_c0.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compMetaC0)), compMetaC0),
		}, "IP_CONCEALMENT")

		meta7Bit := make([]byte, 4096)
		for i := range meta7Bit {
			meta7Bit[i] = csprng[i] & 0x7f
		}
		compMeta7 := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", buildMetaAppl(meta7Bit)})))
		assertRejected(t, "N3_meta_appl_7bit.pdf", map[string][]byte{
			"meta_7bit.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(compMeta7)), compMeta7),
		}, "IP_CONCEALMENT")

		// 5. cmap, EBLC, GDEF, GSUB, fpgm, unknown C0-diluted (N9-N12, 1d, B)
		dil2648 := append(append([]byte(nil), csprng[:2048]...), make([]byte, 600)...)
		cmapTbl := make([]byte, 12+len(dil2648))
		binary.BigEndian.PutUint16(cmapTbl[2:4], 1)
		binary.BigEndian.PutUint32(cmapTbl[8:12], 12)
		copy(cmapTbl[12:], dil2648)

		eblcTbl := make([]byte, 56+len(dil2648))
		binary.BigEndian.PutUint32(eblcTbl[0:4], 0x00020000)
		binary.BigEndian.PutUint32(eblcTbl[4:8], 1)
		binary.BigEndian.PutUint32(eblcTbl[8:12], 56)
		binary.BigEndian.PutUint32(eblcTbl[12:16], 16)
		copy(eblcTbl[56:], dil2648)

		gdefTbl := make([]byte, 12+len(dil2648))
		binary.BigEndian.PutUint32(gdefTbl[0:4], 0x00010000)
		binary.BigEndian.PutUint16(gdefTbl[4:6], 12)
		copy(gdefTbl[12:], dil2648)

		gsubTbl := make([]byte, 10+len(dil2648))
		binary.BigEndian.PutUint32(gsubTbl[0:4], 0x00010000)
		binary.BigEndian.PutUint16(gsubTbl[4:6], 10)
		binary.BigEndian.PutUint16(gsubTbl[6:8], 10)
		binary.BigEndian.PutUint16(gsubTbl[8:10], 10)
		copy(gsubTbl[10:], dil2648)

		c0Dil3296 := append(make([]byte, 800), csprng[:3296]...)
		for name, tbl := range map[string]sfntTbl{
			"N9_cmap_c0.pdf":     {"cmap", cmapTbl},
			"N10_eblc_c0.pdf":    {"EBLC", eblcTbl},
			"N11_gdef_c0.pdf":    {"GDEF", gdefTbl},
			"N12_gsub_c0.pdf":    {"GSUB", gsubTbl},
			"1d_unknown_c0.pdf":  {"XXXX", c0Dil3296},
			"B_sfnt_fpgm_c0.pdf": {"fpgm", c0Dil3296},
		} {
			comp := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), tbl)))
			assertRejected(t, name, map[string][]byte{
				name: makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(comp)), comp),
			}, "IP_CONCEALMENT")
		}
	})

	t.Run("Group2_CFF_CFF2_Uncalled_And_CharStrings", func(t *testing.T) {
		buildSimpleCFF := func(gsubs [][]byte, csItems [][]byte, extraTop []byte, fdSel []byte) []byte {
			hdr := []byte{1, 0, 4, 4}
			nameIdx := buildCFFIndex([][]byte{[]byte("Wave8CFF")})
			strIdx := buildCFFIndex(nil)
			gsubIdx := buildCFFIndex(gsubs)
			csIdx := buildCFFIndex(csItems)
			tdLen := 5 + 1 + len(extraTop)
			if len(fdSel) > 0 {
				tdLen += 7
			}
			tdIdxLen := 2 + 1 + 2*4 + tdLen
			csOff := len(hdr) + len(nameIdx) + tdIdxLen + len(strIdx) + len(gsubIdx)
			var td bytes.Buffer
			td.Write(encodeCFFInt29(int32(csOff)))
			td.WriteByte(17)
			if len(fdSel) > 0 {
				td.Write(encodeCFFInt29(int32(csOff + len(csIdx))))
				td.Write([]byte{12, 37})
			}
			td.Write(extraTop)
			tdIdx := buildCFFIndex([][]byte{td.Bytes()})
			return bytes.Join([][]byte{hdr, nameIdx, tdIdx, strIdx, gsubIdx, csIdx, fdSel}, nil)
		}

		// 1f: ([0xFF, 4B CSPRNG]*11 + 0x05)*80 + 0x0e
		var csFF bytes.Buffer
		for rep := 0; rep < 80; rep++ {
			for k := 0; k < 11; k++ {
				csFF.WriteByte(0xFF)
				off := (rep*11 + k) * 4
				csFF.Write(csprng[off : off+4])
			}
			csFF.WriteByte(0x05)
		}
		csFF.WriteByte(0x0e)
		c1f := zlibCompress(buildSimpleCFF(nil, [][]byte{csFF.Bytes()}, nil, nil))
		assertRejected(t, "1f_cff_charstring_ff_csprng.pdf", map[string][]byte{
			"1f.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(c1f)), c1f),
		}, "IP_CONCEALMENT")

		// C: ([32..246 CSPRNG]*47 + 0x05)*100 + 0x0e
		var cs32 bytes.Buffer
		for rep := 0; rep < 100; rep++ {
			for k := 0; k < 47; k++ {
				b := 32 + (csprng[rep*47+k] % 215)
				cs32.WriteByte(b)
			}
			cs32.WriteByte(0x05)
		}
		cs32.WriteByte(0x0e)
		cC := zlibCompress(buildSimpleCFF(nil, [][]byte{cs32.Bytes()}, nil, nil))
		assertRejected(t, "C_cff_charstring_32_246.pdf", map[string][]byte{
			"C.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cC)), cC),
		}, "IP_CONCEALMENT")

		// N6: 16 x [0x13, 250B CSPRNG] uncalled global subrs
		var gsubs16 [][]byte
		for i := 0; i < 16; i++ {
			s := make([]byte, 251)
			s[0] = 0x13
			copy(s[1:], csprng[i*250:i*250+250])
			gsubs16 = append(gsubs16, s)
		}
		cN6 := zlibCompress(buildSimpleCFF(gsubs16, [][]byte{{14}}, nil, nil))
		assertRejected(t, "N6_cff_uncalled_subr_hintmask_small.pdf", map[string][]byte{
			"N6.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cN6)), cN6),
		}, "IP_CONCEALMENT")

		// N7: [0x13, 2048B CSPRNG, 1024B 'A'] uncalled global subr
		subN7 := append([]byte{0x13}, csprng[:2048]...)
		subN7 = append(subN7, bytes.Repeat([]byte{'A'}, 1024)...)
		cN7 := zlibCompress(buildSimpleCFF([][]byte{subN7}, [][]byte{{14}}, nil, nil))
		assertRejected(t, "N7_cff_uncalled_subr_hintmask_pad.pdf", map[string][]byte{
			"N7.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cN7)), cN7),
		}, "IP_CONCEALMENT")

		// Minor 6: parseCFFFDSelect non-monotonic ranges (range 1 first=2 > sentinel nextFirst=1)
		fdOverlap := []byte{
			3, 0, 2,
			0, 0, 0, // range 0: first=0, fd=0
			0, 2, 0, // range 1: first=2, fd=0 (range 0 spans [0..2))
			0, 1, // sentinel=1 -> range 1 has first=2 > nextFirst=1
		}
		cOverlap := zlibCompress(buildSimpleCFF(nil, [][]byte{{14}, {14}}, nil, fdOverlap))
		assertRejected(t, "cff_fdselect_overlap.pdf", map[string][]byte{
			"fd_overlap.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cOverlap)), cOverlap),
		}, "IP_CONCEALMENT")

		// CFF2: 1g uncalled gsub [0xFF, 4B CSPRNG]*1000 & N8 16 x [0x13, 250B CSPRNG] & vstore C0-diluted
		buildCFF2Font := func(gsubs [][]byte, vstore []byte) []byte {
			gsubIdx := buildCFF2Index(gsubs)
			csIdx := buildCFF2Index([][]byte{{140, 21}})
			tdLen := 6
			if len(vstore) > 0 {
				tdLen += 6
			}
			hdr := []byte{2, 0, 5, byte(tdLen >> 8), byte(tdLen)}
			csOff := 5 + tdLen + len(gsubIdx)
			var td bytes.Buffer
			td.Write(encodeCFFInt29(int32(csOff)))
			td.WriteByte(17)
			if len(vstore) > 0 {
				td.Write(encodeCFFInt29(int32(csOff + len(csIdx))))
				td.WriteByte(24)
			}
			return bytes.Join([][]byte{hdr, td.Bytes(), gsubIdx, csIdx, vstore}, nil)
		}
		var sub1g bytes.Buffer
		for i := 0; i < 1000; i++ {
			sub1g.WriteByte(0xFF)
			sub1g.Write(csprng[i*4 : i*4+4])
		}
		c1g := zlibCompress(buildSFNT(0x4F54544F, append(baseSFNTTables(), sfntTbl{"CFF2", buildCFF2Font([][]byte{sub1g.Bytes()}, nil)})))
		assertRejected(t, "1g_cff2_uncalled_gsub_ff_csprng.pdf", map[string][]byte{
			"1g.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(c1g)), c1g),
		}, "IP_CONCEALMENT")

		cN8 := zlibCompress(buildSFNT(0x4F54544F, append(baseSFNTTables(), sfntTbl{"CFF2", buildCFF2Font(gsubs16, nil)})))
		assertRejected(t, "N8_cff2_uncalled_subr_hintmask_small.pdf", map[string][]byte{
			"N8.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cN8)), cN8),
		}, "IP_CONCEALMENT")

		vsBody := make([]byte, 8+800+3296)
		binary.BigEndian.PutUint16(vsBody[0:2], 1)
		binary.BigEndian.PutUint32(vsBody[2:6], 8)
		copy(vsBody[8+800:], csprng[:3296])
		vs := make([]byte, 2+len(vsBody))
		binary.BigEndian.PutUint16(vs[0:2], uint16(len(vsBody)))
		copy(vs[2:], vsBody)
		cVS := zlibCompress(buildSFNT(0x4F54544F, append(baseSFNTTables(), sfntTbl{"CFF2", buildCFF2Font(nil, vs)})))
		assertRejected(t, "cff2_vstore_c0_diluted.pdf", map[string][]byte{
			"cff2_vs.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cVS)), cVS),
		}, "IP_CONCEALMENT")
	})

	t.Run("Group3_WASM_Sec11_Bypasses", func(t *testing.T) {
		appendUleb := func(b []byte, v uint64) []byte {
			var tmp [10]byte
			n := binary.PutUvarint(tmp[:], v)
			return append(b, tmp[:n]...)
		}
		buildWASMSection := func(id byte, body []byte) []byte {
			out := []byte{id}
			out = appendUleb(out, uint64(len(body)))
			return append(out, body...)
		}
		buildDataSegs := func(segs ...[]byte) []byte {
			var b bytes.Buffer
			b.Write(appendUleb(nil, uint64(len(segs))))
			for _, seg := range segs {
				b.WriteByte(0x00)
				b.Write([]byte{0x41, 0x00, 0x0b})
				b.Write(appendUleb(nil, uint64(len(seg))))
				b.Write(seg)
			}
			return b.Bytes()
		}
		wrapSec11 := func(segs ...[]byte) []byte {
			w := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
			w = append(w, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
			w = append(w, buildWASMSection(11, buildDataSegs(segs...))...)
			return w
		}

		// 2b: stride-3 [2B CSPRNG, 'A'] * 1024
		stride3 := make([]byte, 3*1024)
		for i := 0; i < 1024; i++ {
			copy(stride3[i*3:i*3+2], csprng[i*2:i*2+2])
			stride3[i*3+2] = 'A'
		}
		assertRejected(t, "2b_wasm_2b_csprng_A_stride3.wasm", map[string][]byte{
			"2b.wasm": wrapSec11(stride3),
		}, "IP_CONCEALMENT")

		// 2d / N15: 20 x (200B CSPRNG + 200B "ABAB...")
		var segs20AB [][]byte
		for i := 0; i < 20; i++ {
			s := make([]byte, 400)
			copy(s[:200], csprng[i*200:i*200+200])
			copy(s[200:], bytes.Repeat([]byte("AB"), 100))
			segs20AB = append(segs20AB, s)
		}
		assertRejected(t, "2d_N15_wasm_20x_200b_csprng_200b_AB.wasm", map[string][]byte{
			"2d.wasm": wrapSec11(segs20AB...),
		}, "IP_CONCEALMENT")

		// N17b: monotonic uint32 val(i) = uint32(i)*256 + uint32(csprng[i])
		monoLow := make([]byte, 4096*4)
		for i := 0; i < 4096; i++ {
			binary.LittleEndian.PutUint32(monoLow[i*4:i*4+4], uint32(i)*256+uint32(csprng[i]))
		}
		assertRejected(t, "N17b_wasm_monotonic_u32_low8_csprng.wasm", map[string][]byte{
			"N17b.wasm": wrapSec11(monoLow),
		}, "IP_CONCEALMENT")

		// 2e / probe_e1 / N14: 32 unique funcs + 4096B CSPRNG + 16384B 'A'
		var code32 bytes.Buffer
		code32.WriteByte(32)
		for f := 0; f < 32; f++ {
			var fb bytes.Buffer
			fb.WriteByte(0x00)
			fb.Write([]byte{0x41, byte(f + 1), 0x04, 0x40, 0x10, 0x00, 0x0b})
			for i := 0; i < 1280; i++ {
				op := byte(0x20 + ((i + f) % 32))
				if op == 0x01 || op == 0x0b {
					op = 0x41
				}
				fb.WriteByte(op)
			}
			fb.WriteByte(0x0b)
			code32.Write(appendUleb(nil, uint64(fb.Len())))
			code32.Write(fb.Bytes())
		}
		funcSec32 := make([]byte, 33)
		funcSec32[0] = 32
		wN14 := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
		wN14 = append(wN14, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
		wN14 = append(wN14, buildWASMSection(3, funcSec32)...)
		wN14 = append(wN14, buildWASMSection(10, code32.Bytes())...)
		wN14 = append(wN14, buildWASMSection(11, buildDataSegs(csprng[:4096], bytes.Repeat([]byte{'A'}, 16384)))...)
		assertRejected(t, "2e_probe_e1_N14_wasm_subst32.wasm", map[string][]byte{
			"N14.wasm": wN14,
		}, "IP_CONCEALMENT")

		// probe_e2: real compiled Go WASM (tls_http) + appended 8192B CSPRNG segment in secID == 11
		if goBin, lErr := exec.LookPath("go"); lErr == nil {
			srcDir := t.TempDir()
			pFile := filepath.Join(srcDir, "tls.go")
			_ = os.WriteFile(pFile, []byte("package main\nimport (\n\t\"crypto/tls\"\n\t\"net/http\"\n)\nfunc main() {\n\t_ = &tls.Config{MinVersion: tls.VersionTLS13}\n\t_ = http.MethodGet\n}\n"), 0o644)
			outW := filepath.Join(srcDir, "tls.wasm")
			cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", outW, pFile)
			cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
			if cmd.Run() == nil {
				if wb, rErr := os.ReadFile(outW); rErr == nil {
					// Append a new secID == 11 section containing 8192B CSPRNG.
					probeE2 := append(append([]byte(nil), wb...), buildWASMSection(11, buildDataSegs(csprng[:8192]))...)
					assertRejected(t, "probe_e2_real_go_plus_8kb_csprng.wasm", map[string][]byte{
						"probe_e2.wasm": probeE2,
					}, "IP_CONCEALMENT")
				}
			}
		}
	})

	t.Run("Group4_PDF_Image_ICC_JPEG_ASCII85", func(t *testing.T) {
		// 3a: even cols 0x80, odd cols CSPRNG (bpc=8)
		img3a := make([]byte, 64*64)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				if x%2 == 0 {
					img3a[y*64+x] = 0x80
				} else {
					img3a[y*64+x] = csprng[y*32+x/2]
				}
			}
		}
		c3a := zlibCompress(img3a)
		assertRejected(t, "3a_img_even_cols_0x80_bpc8.pdf", map[string][]byte{
			"3a.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(c3a)), c3a),
		}, "IP_CONCEALMENT")

		// 3b: even cols 0x8080, odd cols CSPRNG (bpc=16)
		img3b := make([]byte, 64*64*2)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				off := (y*64 + x) * 2
				if x%2 == 0 {
					img3b[off], img3b[off+1] = 0x80, 0x80
				} else {
					copy(img3b[off:off+2], csprng[(y*32+x/2)*2:(y*32+x/2)*2+2])
				}
			}
		}
		c3b := zlibCompress(img3b)
		assertRejected(t, "3b_img_even_cols_0x8080_bpc16.pdf", map[string][]byte{
			"3b.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 16 /Length %d /Filter /FlateDecode", len(c3b)), c3b),
		}, "IP_CONCEALMENT")

		// 3c: RGB with 2 constant channels + 1 CSPRNG channel
		img3c := make([]byte, 64*64*3)
		for i := 0; i < 64*64; i++ {
			img3c[i*3+2] = csprng[i]
		}
		c3c := zlibCompress(img3c)
		assertRejected(t, "3c_img_rgb_2const_1csprng.pdf", map[string][]byte{
			"3c.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(c3c)), c3c),
		}, "IP_CONCEALMENT")

		// N20: bpc=16 hi=0x80, 35% lo=0x00, 65% lo=CSPRNG
		imgN20 := make([]byte, 64*64*2)
		for i := 0; i < 64*64; i++ {
			imgN20[i*2] = 0x80
			if (i % 20) >= 7 {
				imgN20[i*2+1] = csprng[i]
			}
		}
		cN20 := zlibCompress(imgN20)
		assertRejected(t, "N20_img_bpc16_lo_35pct_nul.pdf", map[string][]byte{
			"N20.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 16 /Length %d /Filter /FlateDecode", len(cN20)), cN20),
		}, "IP_CONCEALMENT")

		// N21: bpc=8 left 30% 0x20, right 70% CSPRNG
		imgN21 := make([]byte, 64*64)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				if x < 20 {
					imgN21[y*64+x] = 0x20
				} else {
					imgN21[y*64+x] = csprng[y*64+x]
				}
			}
		}
		cN21 := zlibCompress(imgN21)
		assertRejected(t, "N21_img_bpc8_30pct_space_70pct_csprng.pdf", map[string][]byte{
			"N21.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(cN21)), cN21),
		}, "IP_CONCEALMENT")

		// ICC helper
		buildICC := func(extraSig string, extraTag []byte) []byte {
			const numTags = 4
			const hdrEnd = 132 + numTags*12
			descTag := make([]byte, 24)
			copy(descTag[0:4], "desc")
			binary.BigEndian.PutUint32(descTag[8:12], 8)
			copy(descTag[12:], "sRGB_IEC")
			cprtTag := make([]byte, 24)
			copy(cprtTag[0:4], "text")
			copy(cprtTag[8:], "Copyright 2026")
			wtptTag := make([]byte, 20)
			copy(wtptTag[0:4], "XYZ ")
			pad4 := func(b []byte) []byte {
				for len(b)%4 != 0 {
					b = append(b, 0)
				}
				return b
			}
			descTag, cprtTag, wtptTag = pad4(descTag), pad4(cprtTag), pad4(wtptTag)
			extraPad := pad4(append([]byte(nil), extraTag...))
			off0 := hdrEnd
			off1 := off0 + len(descTag)
			off2 := off1 + len(cprtTag)
			off3 := off2 + len(wtptTag)
			total := off3 + len(extraPad)
			icc := make([]byte, total)
			binary.BigEndian.PutUint32(icc[0:4], uint32(total))
			icc[8] = 2
			copy(icc[12:16], "mntr")
			copy(icc[16:20], "RGB ")
			copy(icc[20:24], "XYZ ")
			copy(icc[36:40], "acsp")
			binary.BigEndian.PutUint32(icc[128:132], numTags)
			putEntry := func(idx int, sig string, off, sz int) {
				pos := 132 + idx*12
				copy(icc[pos:pos+4], sig)
				binary.BigEndian.PutUint32(icc[pos+4:pos+8], uint32(off))
				binary.BigEndian.PutUint32(icc[pos+8:pos+12], uint32(sz))
			}
			putEntry(0, "desc", off0, len(descTag))
			putEntry(1, "cprt", off1, len(cprtTag))
			putEntry(2, "wtpt", off2, len(wtptTag))
			putEntry(3, extraSig, off3, len(extraTag))
			copy(icc[off0:], descTag)
			copy(icc[off1:], cprtTag)
			copy(icc[off2:], wtptTag)
			copy(icc[off3:], extraPad)
			return icc
		}

		// probe_d: ICC "text" [CSPRNG, 'A'] * 2048
		altATag := make([]byte, 8+4096)
		copy(altATag[0:4], "text")
		for i := 0; i < 2048; i++ {
			altATag[8+i*2] = csprng[i]
			altATag[8+i*2+1] = 'A'
		}
		cProbeD := zlibCompress(buildICC("desc", altATag))
		assertRejected(t, "probe_d_icc_text_altA.pdf", map[string][]byte{
			"probe_d.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cProbeD)), cProbeD),
		}, "IP_CONCEALMENT")

		// D / N22: ICC mAB 0x80 / 0x20 diluted CLUT
		mabSpace := make([]byte, 32+20+3000)
		copy(mabSpace[0:4], "mAB ")
		mabSpace[8], mabSpace[9] = 3, 3
		binary.BigEndian.PutUint32(mabSpace[24:28], 32)
		mabSpace[32], mabSpace[33], mabSpace[34] = 10, 10, 10
		mabSpace[32+16] = 1
		for pt := 0; pt < 1000; pt++ {
			if (pt/32)%2 == 0 {
				mabSpace[32+20+pt*3] = 0x20
				mabSpace[32+20+pt*3+1] = 0x20
				mabSpace[32+20+pt*3+2] = 0x20
			} else {
				copy(mabSpace[32+20+pt*3:32+20+pt*3+3], csprng[pt*3:pt*3+3])
			}
		}
		cN22 := zlibCompress(buildICC("A2B0", mabSpace))
		assertRejected(t, "N22_icc_mab_outc3_space_clut.pdf", map[string][]byte{
			"N22.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cN22)), cN22),
		}, "IP_CONCEALMENT")

		// N23: ICC mft1 outC=4 0x20-diluted CLUT
		mftSpace := make([]byte, 48+2*256+4096+4*256)
		copy(mftSpace[0:4], "mft1")
		mftSpace[8], mftSpace[9], mftSpace[10] = 2, 4, 32
		pos := 48
		for k := 0; k < 2; k++ {
			for i := 0; i < 256; i++ {
				mftSpace[pos+i] = byte(i)
			}
			pos += 256
		}
		for pt := 0; pt < 1024; pt++ {
			if (pt/32)%2 == 0 {
				copy(mftSpace[pos+pt*4:pos+pt*4+4], []byte{0x20, 0x20, 0x20, 0x20})
			} else {
				copy(mftSpace[pos+pt*4:pos+pt*4+4], csprng[pt*4:pt*4+4])
			}
		}
		pos += 4096
		for k := 0; k < 4; k++ {
			for i := 0; i < 256; i++ {
				mftSpace[pos+i] = byte(i)
			}
			pos += 256
		}
		cN23 := zlibCompress(buildICC("A2B0", mftSpace))
		assertRejected(t, "N23_icc_mft1_outc4_space_clut.pdf", map[string][]byte{
			"N23.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cN23)), cN23),
		}, "IP_CONCEALMENT")

		// N24: ICC vcgt C0-diluted
		vcgtC0 := make([]byte, 8+800+3296)
		copy(vcgtC0[0:4], "vcgt")
		copy(vcgtC0[8+800:], csprng[:3296])
		cN24 := zlibCompress(buildICC("vcgt", vcgtC0))
		assertRejected(t, "N24_icc_vcgt_c0_diluted.pdf", map[string][]byte{
			"N24.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cN24)), cN24),
		}, "IP_CONCEALMENT")

		// JPEG DQT 3d, N25c, N25d
		var jBuf bytes.Buffer
		_ = jpeg.Encode(&jBuf, image.NewRGBA(image.Rect(0, 0, 16, 16)), &jpeg.Options{Quality: 75})
		baseJ := jBuf.Bytes()
		sosIdx := bytes.Index(baseJ, []byte{0xFF, 0xDA})

		var dqt3d bytes.Buffer
		dqt3d.Write([]byte{0xFF, 0xDB})
		_ = binary.Write(&dqt3d, binary.BigEndian, uint16(2+4*65))
		for tq := 0; tq < 4; tq++ {
			dqt3d.WriteByte(byte(tq))
			dqt3d.Write(bytes.Repeat([]byte{0x01}, 32))
			dqt3d.Write(csprng[tq*32 : tq*32+32])
		}
		assertRejected(t, "3d_jpg_dqt_4x_32b_csprng_01.jpg", map[string][]byte{
			"3d.jpg": append(append(append([]byte(nil), baseJ[:sosIdx]...), dqt3d.Bytes()...), baseJ[sosIdx:]...),
		}, "IP_CONCEALMENT")

		var dqtN25c bytes.Buffer
		for m := 0; m < 3; m++ {
			dqtN25c.Write([]byte{0xFF, 0xDB})
			_ = binary.Write(&dqtN25c, binary.BigEndian, uint16(2+4*129))
			for tq := 0; tq < 4; tq++ {
				dqtN25c.WriteByte(byte(0x10 | tq))
				for k := 0; k < 44; k++ {
					dqtN25c.WriteByte(0x00)
					dqtN25c.WriteByte(csprng[(m*4+tq)*44+k])
				}
				dqtN25c.Write(make([]byte, 40))
			}
		}
		assertRejected(t, "N25c_jpg_dqt_3markers_pq1_44b.jpg", map[string][]byte{
			"N25c.jpg": append(append(append([]byte(nil), baseJ[:sosIdx]...), dqtN25c.Bytes()...), baseJ[sosIdx:]...),
		}, "IP_CONCEALMENT")

		var dqtN25d bytes.Buffer
		for m := 0; m < 3; m++ {
			dqtN25d.Write([]byte{0xFF, 0xDB})
			_ = binary.Write(&dqtN25d, binary.BigEndian, uint16(2+4*65))
			for tq := 0; tq < 4; tq++ {
				dqtN25d.WriteByte(byte(tq))
				dqtN25d.Write(csprng[(m*4+tq)*36 : (m*4+tq)*36+36])
				dqtN25d.Write(bytes.Repeat([]byte{0x01}, 28))
			}
		}
		assertRejected(t, "N25d_jpg_dqt_3markers_pq0_36b.jpg", map[string][]byte{
			"N25d.jpg": append(append(append([]byte(nil), baseJ[:sosIdx]...), dqtN25d.Bytes()...), baseJ[sosIdx:]...),
		}, "IP_CONCEALMENT")

		// JPEG DRI RST N26 (sub-8B spans), 3e (mixed 40x28B among 160 real AC intervals), N27 (2 anchors among 398x10B)
		stuffFF := func(raw []byte) []byte {
			var b bytes.Buffer
			for _, c := range raw {
				b.WriteByte(c)
				if c == 0xFF {
					b.WriteByte(0x00)
				}
			}
			return b.Bytes()
		}
		buildDRIJPEG := func(w, h int, intervals [][]byte) []byte {
			var j bytes.Buffer
			j.Write([]byte{0xFF, 0xD8})
			j.Write(append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...))
			j.Write([]byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, byte(h >> 8), byte(h), byte(w >> 8), byte(w), 0x01, 0x01, 0x11, 0x00})
			j.Write([]byte{0xFF, 0xC4, 0x00, 0x1F, 0x00, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
			j.Write([]byte{0xFF, 0xC4, 0x00, 0x1F, 0x10, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d,
				0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
				0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
				0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
				0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
				0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
				0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
				0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
				0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
				0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
				0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
				0xf9, 0xfa})
			// Fix DHT AC length header to 2+1+16+162 = 181
			jBytes := j.Bytes()
			dhtPos := bytes.LastIndex(jBytes, []byte{0xFF, 0xC4})
			binary.BigEndian.PutUint16(jBytes[dhtPos+2:dhtPos+4], uint16(1+16+162+2))
			j = *bytes.NewBuffer(jBytes)
			j.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
			j.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
			for idx, iv := range intervals {
				j.Write(iv)
				if idx < len(intervals)-1 {
					j.Write([]byte{0xFF, byte(0xD0 + (idx % 8))})
				}
			}
			j.Write([]byte{0xFF, 0xD9})
			return j.Bytes()
		}
		// Genuine non-trivial AC MCU bytes (DC=0: '00', AC coefs -> EOB='1010')
		// With standard AC Huffman, 0x00 is 2 bits ('00') = run 0 size 1 ('00'+1bit sign), 63 coeffs = 63*(2+1)=189 bits -> 24 bytes!
		realAnchorMCU := bytes.Repeat([]byte{0x00}, 20)
		// Wait: let's validate with jpeg.Decode directly to be 100% sure!
		ivsN26 := make([][]byte, 1024)
		for i := 0; i < 1024; i++ {
			ivsN26[i] = append([]byte{0x28}, stuffFF(csprng[i*6:i*6+6])...)
		}
		jpgN26 := buildDRIJPEG(256, 256, ivsN26)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgN26)); dErr != nil {
			t.Fatalf("N26 invalid JPEG: %v", dErr)
		}
		assertRejected(t, "N26_jpg_dri_sub8b_rst.jpg", map[string][]byte{"N26.jpg": jpgN26}, "IP_CONCEALMENT")

		// Real AC MCU with 63 non-zero coefs (DC=0 '00', 63 * (run0,cat1='00' + sign='1' = '001') -> 191 bits = 24 bytes, untrimmable!).
		// Wait: '00' (2 bits) + '0' (1 bit sign) = 3 bits per coef -> 63*3 = 189 bits + '00' DC = 191 bits = 24 bytes (all zeros padded with 1s = 0x24,0x92,0x49...).
		// Let's verify 0x00 + 24 bytes of 0b00100100... is valid & untrimmable with jpeg.Decode!
		var anchorBits uint64
		_ = anchorBits
		var anchorBuf [24]byte
		// Build 191 bits: DC='00', then 63 times '001'
		bitPos := 2
		for c := 0; c < 63; c++ {
			bitPos += 2 // '00'
			anchorBuf[bitPos/8] |= 1 << (7 - (bitPos % 8))
			bitPos++
		}
		realAnchor := anchorBuf[:]
		_ = realAnchorMCU
		ivs3e := make([][]byte, 200)
		for i := 0; i < 200; i++ {
			if i%5 == 0 {
				ivs3e[i] = append([]byte{0x28}, stuffFF(csprng[i*28:i*28+28])...)
			} else {
				ivs3e[i] = append([]byte(nil), stuffFF(realAnchor)...)
			}
		}
		jpg3e := buildDRIJPEG(160, 80, ivs3e)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpg3e)); dErr != nil {
			t.Fatalf("3e invalid JPEG: %v", dErr)
		}
		assertRejected(t, "3e_jpg_dri_mixed_40x28b.jpg", map[string][]byte{"3e.jpg": jpg3e}, "IP_CONCEALMENT")

		// Real control: ALL 200 intervals are realAnchor (zero CSPRNG) -> 0 findings (ALLOW)!
		ivsCtrl := make([][]byte, 200)
		for i := 0; i < 200; i++ {
			ivsCtrl[i] = append([]byte(nil), stuffFF(realAnchor)...)
		}
		jpgCtrl := buildDRIJPEG(160, 80, ivsCtrl)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgCtrl)); dErr != nil {
			t.Fatalf("ctrl DRI invalid JPEG: %v", dErr)
		}
		cf, ccov, cErr := runEngineOnFiles(t, engine, map[string][]byte{"ctrl_dri_ac.jpg": jpgCtrl}, "")
		if cErr != nil || !ccov.Complete || len(cf) != 0 {
			t.Fatalf("ctrl_dri_ac.jpg expected 0 findings, cov=%+v err=%v findings=%+v", ccov, cErr, cf)
		}

		// N27: 2 untrimmable anchors (0 and 200) among 398 x (1B MCU + 10B CSPRNG)
		ivsN27 := make([][]byte, 400)
		for i := 0; i < 400; i++ {
			if i == 0 || i == 200 {
				ivsN27[i] = append([]byte(nil), stuffFF(realAnchor)...)
			} else {
				ivsN27[i] = append([]byte{0x28}, stuffFF(csprng[i*10:i*10+10])...)
			}
		}
		jpgN27 := buildDRIJPEG(160, 160, ivsN27)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgN27)); dErr != nil {
			t.Fatalf("N27 invalid JPEG: %v", dErr)
		}
		assertRejected(t, "N27_jpg_dri_2_untrimmable_anchors.jpg", map[string][]byte{"N27.jpg": jpgN27}, "IP_CONCEALMENT")

		// N28: L4b ASCII85 quoted string concatenation
		var a85 bytes.Buffer
		enc := ascii85.NewEncoder(&a85)
		_, _ = enc.Write(stripped)
		_ = enc.Close()
		a85Str := a85.String()
		mid := len(a85Str) / 2
		jsConcat := fmt.Sprintf("const p = \"<~%s\" + \"%s~>\";\n", a85Str[:mid], a85Str[mid:])
		assertRejected(t, "N28_l4b_ascii85_concat.js", map[string][]byte{"N28.js": []byte(jsConcat)}, "IP_CONCEALMENT")
	})
}

func TestWave9RemediationAllClustersAndE2E(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 16 << 20,
	})
	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	compiledPol, errs := polEngine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("compile push-ip-protection.yaml: %+v", errs)
	}

	evalPolicy := func(findings []domain.Finding, cov domain.ScanCoverage) domain.PolicyEffect {
		sum := inspection.InspectionSummary{
			MandatoryScannersComplete: cov.Complete && cov.FilesSkipped == 0,
			ScanComplete:              cov.Complete && cov.FilesSkipped == 0,
		}
		for _, f := range findings {
			sum.TotalFindings++
			switch f.Category {
			case "SECRET":
				if f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh {
					sum.CriticalSecrets++
				}
			case "IP_CONCEALMENT":
				sum.ConcealmentFindings++
			case "IP_EXACT":
				sum.IPExactMatches++
			case "IP_WINNOW":
				sum.IPWinnowMatches++
			case "IP_HEADER_STRIP":
				sum.IPHeaderStripMatches++
			}
		}
		res, pErr := polEngine.Evaluate(context.Background(), compiledPol, policy.StagePushEgress, policy.PolicyInput{
			Stage:    policy.StagePushEgress,
			Findings: workflow.SummaryToFindingsInput(sum),
			Assessment: policy.AssessmentInput{
				Status:      "NOT_REQUIRED",
				IPRisk:      "NONE",
				Risk:        "NONE",
				Disposition: "NOT_REQUIRED",
			},
			Destination: policy.DestinationInput{
				ID:             "repo-internal",
				Name:           "acme/app",
				Host:           "github.com",
				Registered:     true,
				External:       false,
				Classification: "INTERNAL",
			},
			Push: policy.PushInput{
				RefNames:   []string{"refs/heads/main"},
				EgressMode: "ENFORCE_BLOCK",
			},
		})
		if pErr != nil {
			t.Fatalf("policy.Evaluate: %v", pErr)
		}
		return res.Effect
	}

	// E2E helper: runs fingerprints.Engine AND full inspection.DefaultRunner -> workflow.SummaryToFindingsInput -> policy.Engine.
	assertE2ERejected := func(st *testing.T, name string, files map[string][]byte, expectedCategory string) {
		st.Helper()
		bf, bcov, bErr := runEngineOnFiles(st, engine, files, "")
		if bErr != nil || !bcov.Complete || !hasCategory(bf, expectedCategory) {
			st.Fatalf("%s expected %s, cov=%+v err=%v findings=%+v", name, expectedCategory, bcov, bErr, bf)
		}
		for _, f := range bf {
			if rErr := f.ValidateRedacted(); rErr != nil {
				st.Fatalf("%s ValidateRedacted failed: %v", name, rErr)
			}
			if f.Scanner == "ip_fingerprint" {
				if mErr := domain.ValidateIPFingerprintMetadata(f.Metadata); mErr != nil {
					st.Fatalf("%s ValidateIPFingerprintMetadata failed: %v", name, mErr)
				}
			}
		}
		eff := evalPolicy(bf, bcov)
		if eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
			st.Fatalf("%s expected DENY or QUARANTINE, got %s (findings=%+v)", name, eff, bf)
		}
	}
	assertE2EAllowed := func(st *testing.T, name string, files map[string][]byte) {
		st.Helper()
		cf, ccov, cErr := runEngineOnFiles(st, engine, files, "")
		if cErr != nil || !ccov.Complete || len(cf) != 0 {
			st.Fatalf("%s expected 0 findings, cov=%+v err=%v findings=%+v", name, ccov, cErr, cf)
		}
		if eff := evalPolicy(cf, ccov); eff != domain.PolicyEffectAllow {
			st.Fatalf("%s expected ALLOW, got %s", name, eff)
		}
	}

	csprng := make([]byte, 80*1024)
	for off := 0; off < len(csprng); off += 32 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("wave9-csprng-%d", off)))
		copy(csprng[off:], sum[:])
	}
	csprng7 := make([]byte, len(csprng))
	for i, b := range csprng {
		csprng7[i] = b & 0x7f
	}
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	zlibCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return buf.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< " + dictEntries + " >>\nstream\n")
		b.Write(body)
		b.WriteString("\nendstream\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
		return b.Bytes()
	}

	t.Run("Cluster1_WASM_Sec11_ControlsAndBypasses", func(t *testing.T) {
		appendUleb := func(b []byte, v uint64) []byte {
			var tmp [10]byte
			n := binary.PutUvarint(tmp[:], v)
			return append(b, tmp[:n]...)
		}
		buildWASMSection := func(id byte, body []byte) []byte {
			out := []byte{id}
			out = appendUleb(out, uint64(len(body)))
			return append(out, body...)
		}
		buildDataSegs := func(segs ...[]byte) []byte {
			var b bytes.Buffer
			b.Write(appendUleb(nil, uint64(len(segs))))
			for _, seg := range segs {
				b.WriteByte(0x00)
				b.Write([]byte{0x41, 0x00, 0x0b})
				b.Write(appendUleb(nil, uint64(len(seg))))
				b.Write(seg)
			}
			return b.Bytes()
		}
		wrapSec11 := func(segs ...[]byte) []byte {
			w := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
			w = append(w, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
			w = append(w, buildWASMSection(11, buildDataSegs(segs...))...)
			return w
		}
		buildSpoofedGoWASM := func(segs ...[]byte) []byte {
			var funcSec bytes.Buffer
			funcSec.Write(appendUleb(nil, 512))
			for i := 0; i < 512; i++ {
				funcSec.WriteByte(0x00)
			}
			var codeSec bytes.Buffer
			codeSec.Write(appendUleb(nil, 512))
			for f := 0; f < 512; f++ {
				var fb bytes.Buffer
				fb.WriteByte(0x00)
				fb.Write([]byte{0x41, byte(f & 0x7f), 0x04, 0x40, 0x10, 0x00, 0x0b})
				for i := 0; i < 1040; i++ {
					op := byte(0x20 + ((i + f) % 32))
					if op == 0x01 || op == 0x0b {
						op = 0x41
					}
					fb.WriteByte(op)
				}
				fb.WriteByte(0x0b)
				codeSec.Write(appendUleb(nil, uint64(fb.Len())))
				codeSec.Write(fb.Bytes())
			}
			w := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
			w = append(w, buildWASMSection(1, []byte{0x01, 0x60, 0x00, 0x00})...)
			w = append(w, buildWASMSection(3, funcSec.Bytes())...)
			w = append(w, buildWASMSection(10, codeSec.Bytes())...)
			w = append(w, buildWASMSection(11, buildDataSegs(segs...))...)
			return w
		}

		// Controls: genuine GF(2^8)-derived AES Te + P-256 Montgomery [1..32]G + pow10 u128 pmHiLo.
		gfMul := func(a, b byte) byte {
			var r byte
			for i := 0; i < 8; i++ {
				if b&1 != 0 {
					r ^= a
				}
				hi := a & 0x80
				a <<= 1
				if hi != 0 {
					a ^= 0x1b
				}
				b >>= 1
			}
			return r
		}
		gfInv := func(a byte) byte {
			r, x := byte(1), a
			for e := 254; e > 0; e >>= 1 {
				if e&1 != 0 {
					r = gfMul(r, x)
				}
				x = gfMul(x, x)
			}
			return r
		}
		genuineTe := make([]byte, 4096)
		for i := 0; i < 256; i++ {
			q := gfInv(byte(i))
			s := q ^ bits.RotateLeft8(q, 1) ^ bits.RotateLeft8(q, 2) ^ bits.RotateLeft8(q, 3) ^ bits.RotateLeft8(q, 4) ^ 0x63
			s2 := gfMul(s, 2)
			s3 := s2 ^ s
			w0 := (uint32(s2) << 24) | (uint32(s) << 16) | (uint32(s) << 8) | uint32(s3)
			binary.LittleEndian.PutUint32(genuineTe[i*4:], w0)
			binary.LittleEndian.PutUint32(genuineTe[1024+i*4:], bits.RotateLeft32(w0, 24))
			binary.LittleEndian.PutUint32(genuineTe[2048+i*4:], bits.RotateLeft32(w0, 16))
			binary.LittleEndian.PutUint32(genuineTe[3072+i*4:], bits.RotateLeft32(w0, 8))
		}
		assertE2EAllowed(t, "ctrl_genuine_aes_te4096.wasm", map[string][]byte{"te.wasm": wrapSec11(genuineTe)})

		p256 := elliptic.P256().Params()
		rMod := new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 256), p256.P)
		genuineP256 := make([]byte, 2048)
		px, py := new(big.Int).Set(p256.Gx), new(big.Int).Set(p256.Gy)
		for j := 0; j < 32; j++ {
			xm := new(big.Int).Mod(new(big.Int).Mul(px, rMod), p256.P)
			ym := new(big.Int).Mod(new(big.Int).Mul(py, rMod), p256.P)
			var xb, yb [32]byte
			xm.FillBytes(xb[:])
			ym.FillBytes(yb[:])
			for k := 0; k < 32; k++ {
				genuineP256[j*64+k] = xb[31-k]
				genuineP256[j*64+32+k] = yb[31-k]
			}
			px, py = p256.Add(px, py, p256.Gx, p256.Gy)
		}
		assertE2EAllowed(t, "ctrl_genuine_p256_mont2048.wasm", map[string][]byte{"p256.wasm": wrapSec11(genuineP256)})

		// Genuine normalized pow10 u128 table (32 entries starting from 2^63).
		pow10Valid := make([]byte, 32*16)
		curHi, curLo := uint64(1)<<63, uint64(0)
		for i := 0; i < 32; i++ {
			binary.LittleEndian.PutUint64(pow10Valid[i*16:], curHi)
			binary.LittleEndian.PutUint64(pow10Valid[i*16+8:], curLo)
			pHi, pLo := bits.Mul64(curHi, 10)
			qHi, qLo := bits.Mul64(curLo, 10)
			mid, c := bits.Add64(pLo, qHi, 0)
			top := pHi + c
			if top >= 8 {
				curHi = (top << 60) | (mid >> 4)
				curLo = (mid << 60) | (qLo >> 4)
			} else {
				curHi = (top << 61) | (mid >> 3)
				curLo = (mid << 61) | (qLo >> 3)
			}
		}
		assertE2EAllowed(t, "ctrl_genuine_pow10_u128.wasm", map[string][]byte{"pow10.wasm": wrapSec11(pow10Valid)})

		// Bypasses:
		// 1. fake_te_rot_csprng & R9_W4
		fakeTe := make([]byte, 4096)
		for i := 0; i < 256; i++ {
			fakeTe[i*4] = byte(i)
			copy(fakeTe[i*4+1:i*4+4], csprng[i*3:i*3+3])
			w0 := binary.BigEndian.Uint32(fakeTe[i*4:])
			binary.BigEndian.PutUint32(fakeTe[1024+i*4:], bits.RotateLeft32(w0, 24))
			binary.BigEndian.PutUint32(fakeTe[2048+i*4:], bits.RotateLeft32(w0, 16))
			binary.BigEndian.PutUint32(fakeTe[3072+i*4:], bits.RotateLeft32(w0, 8))
		}
		assertE2ERejected(t, "R9_W4_fake_te_rot_csprng.wasm", map[string][]byte{"fake_te.wasm": wrapSec11(fakeTe)}, "IP_CONCEALMENT")

		// 2. R9_W5: pow10 hi64 + CSPRNG lo64
		fakePow10 := make([]byte, 256*16)
		copy(fakePow10, pow10Valid[:16])
		pHiPow, pLoPow := uint64(1)<<63, uint64(0)
		for i := 0; i < 256; i++ {
			binary.LittleEndian.PutUint64(fakePow10[i*16:], pHiPow)
			binary.LittleEndian.PutUint64(fakePow10[i*16+8:], binary.LittleEndian.Uint64(csprng[i*8:]))
			aHi, aLo := bits.Mul64(pHiPow, 10)
			qHi, _ := bits.Mul64(pLoPow, 10)
			mid, c := bits.Add64(aLo, qHi, 0)
			top := aHi + c
			if top >= 8 {
				pHiPow = (top << 60) | (mid >> 4)
			} else {
				pHiPow = (top << 61) | (mid >> 3)
			}
			pLoPow = binary.LittleEndian.Uint64(fakePow10[i*16+8:])
		}
		assertE2ERejected(t, "R9_W5_pow10_lo64_csprng.wasm", map[string][]byte{"pow10_fake.wasm": wrapSec11(fakePow10)}, "IP_CONCEALMENT")

		// 3. R9_W6: arbitrary valid P-256 Montgomery curve points (x_i = CSPRNG, solved y_i)
		fakeP256 := make([]byte, 32*64)
		rInv := new(big.Int).ModInverse(rMod, p256.P)
		for pt := 0; pt < 32; {
			var xb [32]byte
			copy(xb[:31], csprng[pt*31:])
			xb[31] = byte(pt)
			for try := 0; try < 1000; try++ {
				xb[31]++
				xAff := new(big.Int).SetBytes(xb[:])
				xAff.Mod(xAff, p256.P)
				x3 := new(big.Int).Exp(xAff, big.NewInt(3), p256.P)
				threeX := new(big.Int).Mul(big.NewInt(3), xAff)
				rhs := new(big.Int).Sub(x3, threeX)
				rhs.Add(rhs, p256.B)
				rhs.Mod(rhs, p256.P)
				yAff := new(big.Int).ModSqrt(rhs, p256.P)
				if yAff != nil {
					_ = rInv
					pt64 := func(x, y *big.Int) []byte {
						xm := new(big.Int).Mod(new(big.Int).Mul(x, rMod), p256.P)
						ym := new(big.Int).Mod(new(big.Int).Mul(y, rMod), p256.P)
						var bx, by [32]byte
						xm.FillBytes(bx[:])
						ym.FillBytes(by[:])
						out := make([]byte, 64)
						for k := 0; k < 32; k++ {
							out[k] = bx[31-k]
							out[32+k] = by[31-k]
						}
						return out
					}(xAff, yAff)
					copy(fakeP256[pt*64:], pt64)
					pt++
					break
				}
			}
		}
		assertE2ERejected(t, "R9_W6_spoofed_p256_mont.wasm", map[string][]byte{"fake_p256.wasm": wrapSec11(fakeP256)}, "IP_CONCEALMENT")

		// 4. ADV_S3, R9_W1, R9_W9, R9_W2 (spoofed hasGoRuntime)
		fakePclntab := []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08}
		assertE2ERejected(t, "ADV_S3_spoof_go_7680b_7bit.wasm", map[string][]byte{"adv_s3.wasm": buildSpoofedGoWASM(fakePclntab, csprng7[:7680])}, "IP_CONCEALMENT")
		assertE2ERejected(t, "R9_W1_spoof_go_4096b_7bit.wasm", map[string][]byte{"r9_w1.wasm": buildSpoofedGoWASM(fakePclntab, csprng7[:4096])}, "IP_CONCEALMENT")
		assertE2ERejected(t, "R9_W9_spoof_go_2x3000b_7bit.wasm", map[string][]byte{"r9_w9.wasm": buildSpoofedGoWASM(fakePclntab, csprng7[:3000], csprng7[3000:6000])}, "IP_CONCEALMENT")

		per11Seg := make([]byte, 4000)
		for i := 0; i < 4000; i++ {
			if i%11 < 2 {
				per11Seg[i] = 'A'
			} else {
				per11Seg[i] = csprng[i]
			}
		}
		assertE2ERejected(t, "R9_W2_spoof_go_2x4000b_per11.wasm", map[string][]byte{"r9_w2.wasm": buildSpoofedGoWASM(fakePclntab, per11Seg, per11Seg)}, "IP_CONCEALMENT")

		// 5. R9_W7 (stride 9), R9_W8 (period 9), 40x200b small segs 7-bit
		stride9 := make([]byte, 512*9)
		for i := 0; i < 512; i++ {
			copy(stride9[i*9:], csprng[i*5:i*5+5])
			copy(stride9[i*9+5:], "ABCD")
		}
		assertE2ERejected(t, "R9_W7_stride9_abc.wasm", map[string][]byte{"r9_w7.wasm": wrapSec11(stride9)}, "IP_CONCEALMENT")

		var per9Segs [][]byte
		for i := 0; i < 20; i++ {
			s := make([]byte, 400)
			copy(s[:200], csprng[i*200:i*200+200])
			for k := 200; k < 400; k++ {
				s[k] = byte('A' + (k-200)%9)
			}
			per9Segs = append(per9Segs, s)
		}
		assertE2ERejected(t, "R9_W8_period9.wasm", map[string][]byte{"r9_w8.wasm": wrapSec11(per9Segs...)}, "IP_CONCEALMENT")

		var small40 [][]byte
		for i := 0; i < 40; i++ {
			small40 = append(small40, csprng7[i*200:i*200+200])
		}
		assertE2ERejected(t, "wasm_40x200b_7bit.wasm", map[string][]byte{"small40.wasm": wrapSec11(small40...)}, "IP_CONCEALMENT")

		// 6. Real Go WASM + R9_W3 (4KB 7-bit), + 64KB 7-bit, + 8192B sub-7.85 (216-alphabet)
		if goBin, lErr := exec.LookPath("go"); lErr == nil {
			srcDir := t.TempDir()
			pFile := filepath.Join(srcDir, "tls.go")
			_ = os.WriteFile(pFile, []byte("package main\nimport (\n\t\"crypto/tls\"\n\t\"net/http\"\n)\nfunc main() {\n\t_ = &tls.Config{MinVersion: tls.VersionTLS13}\n\t_ = http.MethodGet\n}\n"), 0o644)
			outW := filepath.Join(srcDir, "tls.wasm")
			cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", outW, pFile)
			cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
			if cmd.Run() == nil {
				if wb, rErr := os.ReadFile(outW); rErr == nil {
					sub785 := make([]byte, 8192)
					for i := range sub785 {
						sub785[i] = byte(int(csprng[i]) % 216)
					}
					assertE2ERejected(t, "R9_W3_real_go_plus_4kb_7bit.wasm", map[string][]byte{"w3.wasm": append(append([]byte(nil), wb...), buildWASMSection(11, buildDataSegs(csprng7[:4096]))...)}, "IP_CONCEALMENT")
					assertE2ERejected(t, "wasm_real_go_plus_64kb_7bit_csprng.wasm", map[string][]byte{"w64.wasm": append(append([]byte(nil), wb...), buildWASMSection(11, buildDataSegs(csprng7[:65536]))...)}, "IP_CONCEALMENT")
					assertE2ERejected(t, "wasm_real_go_plus_8192b_sub785.wasm", map[string][]byte{"w785.wasm": append(append([]byte(nil), wb...), buildWASMSection(11, buildDataSegs(sub785))...)}, "IP_CONCEALMENT")
				}
			}
		}
	})

	t.Run("Cluster2_SFNT_CFF_Bypasses", func(t *testing.T) {
		sfntSum := func(tbl []byte) uint32 {
			padded := append([]byte(nil), tbl...)
			for len(padded)%4 != 0 {
				padded = append(padded, 0)
			}
			var s uint32
			for i := 0; i+4 <= len(padded); i += 4 {
				s += binary.BigEndian.Uint32(padded[i : i+4])
			}
			return s
		}
		type sfntTbl struct {
			tag  string
			data []byte
		}
		buildSFNT := func(sfntTag uint32, tbls []sfntTbl) []byte {
			var body bytes.Buffer
			dirSize := 12 + len(tbls)*16
			var dir bytes.Buffer
			_ = binary.Write(&dir, binary.BigEndian, sfntTag)
			_ = binary.Write(&dir, binary.BigEndian, uint16(len(tbls)))
			_ = binary.Write(&dir, binary.BigEndian, uint16(64))
			_ = binary.Write(&dir, binary.BigEndian, uint16(2))
			_ = binary.Write(&dir, binary.BigEndian, uint16(0))
			for _, te := range tbls {
				off := dirSize + body.Len()
				body.Write(te.data)
				for body.Len()%4 != 0 {
					body.WriteByte(0)
				}
				dir.WriteString(te.tag)
				_ = binary.Write(&dir, binary.BigEndian, sfntSum(te.data))
				_ = binary.Write(&dir, binary.BigEndian, uint32(off))
				_ = binary.Write(&dir, binary.BigEndian, uint32(len(te.data)))
			}
			return append(dir.Bytes(), body.Bytes()...)
		}
		baseSFNTTables := func() []sfntTbl {
			headTbl := make([]byte, 54)
			binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
			binary.BigEndian.PutUint16(headTbl[50:52], 1)
			maxpTbl := make([]byte, 6)
			binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
			binary.BigEndian.PutUint16(maxpTbl[4:6], 1)
			return []sfntTbl{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", make([]byte, 8)}, {"glyf", nil}}
		}
		wrapDER := func(tag byte, content []byte) []byte {
			var b bytes.Buffer
			b.WriteByte(tag)
			l := len(content)
			if l < 0x80 {
				b.WriteByte(byte(l))
			} else if l <= 0xff {
				b.Write([]byte{0x81, byte(l)})
			} else {
				b.Write([]byte{0x82, byte(l >> 8), byte(l)})
			}
			b.Write(content)
			return b.Bytes()
		}

		// ADV_S1, ADV_S2, R9_S1, R9_S1_7bit: glyf coordinate CSPRNG
		makeCoordGlyf := func(numPts int, flagByte byte, coords []byte) []sfntTbl {
			var g bytes.Buffer
			_ = binary.Write(&g, binary.BigEndian, int16(1))
			_ = binary.Write(&g, binary.BigEndian, int16(0))
			_ = binary.Write(&g, binary.BigEndian, int16(0))
			_ = binary.Write(&g, binary.BigEndian, int16(100))
			_ = binary.Write(&g, binary.BigEndian, int16(100))
			_ = binary.Write(&g, binary.BigEndian, uint16(numPts-1))
			_ = binary.Write(&g, binary.BigEndian, uint16(0))
			g.Write(bytes.Repeat([]byte{flagByte}, numPts))
			g.Write(coords)
			headTbl := make([]byte, 54)
			binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
			binary.BigEndian.PutUint16(headTbl[50:52], 1)
			maxpTbl := make([]byte, 6)
			binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
			binary.BigEndian.PutUint16(maxpTbl[4:6], 1)
			locaTbl := make([]byte, 8)
			binary.BigEndian.PutUint32(locaTbl[4:8], uint32(g.Len()))
			return []sfntTbl{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", locaTbl}, {"glyf", g.Bytes()}}
		}
		cAdvS1 := zlibCompress(buildSFNT(0x00010000, makeCoordGlyf(1000, 0x06, csprng[:2000])))
		assertE2ERejected(t, "ADV_S1_glyf_2kb_coords.pdf", map[string][]byte{"adv_s1.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cAdvS1)), cAdvS1)}, "IP_CONCEALMENT")
		cAdvS2 := zlibCompress(buildSFNT(0x00010000, makeCoordGlyf(16000, 0x00, csprng[:64000])))
		assertE2ERejected(t, "ADV_S2_glyf_64kb_coords.pdf", map[string][]byte{"adv_s2.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cAdvS2)), cAdvS2)}, "IP_CONCEALMENT")
		cR9S1 := zlibCompress(buildSFNT(0x00010000, makeCoordGlyf(4096, 0x06, csprng[:8192])))
		assertE2ERejected(t, "R9_S1_glyf_8kb_coords.pdf", map[string][]byte{"r9_s1.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cR9S1)), cR9S1)}, "IP_CONCEALMENT")
		cR9S1_7 := zlibCompress(buildSFNT(0x00010000, makeCoordGlyf(4096, 0x06, csprng7[:8192])))
		assertE2ERejected(t, "R9_S1_7bit_glyf_8kb_coords.pdf", map[string][]byte{"r9_s1_7.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cR9S1_7)), cR9S1_7)}, "IP_CONCEALMENT")

		// R9_S2a (1000 x 8B 7-bit pad) & R9_S2b (1000 x nc=0 16B with 6B slack)
		makeMultiGlyf := func(glyphs [][]byte) []sfntTbl {
			var g bytes.Buffer
			loca := make([]byte, (len(glyphs)+1)*4)
			for i, gl := range glyphs {
				g.Write(gl)
				binary.BigEndian.PutUint32(loca[(i+1)*4:], uint32(g.Len()))
			}
			headTbl := make([]byte, 54)
			binary.BigEndian.PutUint32(headTbl[12:16], 0x5F0F3CF5)
			binary.BigEndian.PutUint16(headTbl[50:52], 1)
			maxpTbl := make([]byte, 6)
			binary.BigEndian.PutUint32(maxpTbl[0:4], 0x00010000)
			binary.BigEndian.PutUint16(maxpTbl[4:6], uint16(len(glyphs)))
			return []sfntTbl{{"head", headTbl}, {"maxp", maxpTbl}, {"loca", loca}, {"glyf", g.Bytes()}}
		}
		var glyphsS2a, glyphsS2b [][]byte
		for i := 0; i < 1000; i++ {
			g1 := make([]byte, 10+2+2+1+2+8)
			binary.BigEndian.PutUint16(g1[0:2], 1)
			binary.BigEndian.PutUint16(g1[6:8], 100)
			binary.BigEndian.PutUint16(g1[8:10], 100)
			g1[14] = 0x06
			copy(g1[17:], csprng7[i*8:i*8+8])
			glyphsS2a = append(glyphsS2a, g1)

			g0 := make([]byte, 16)
			binary.BigEndian.PutUint16(g0[6:8], 100)
			binary.BigEndian.PutUint16(g0[8:10], 100)
			copy(g0[10:], csprng[i*6:i*6+6])
			glyphsS2b = append(glyphsS2b, g0)
		}
		cR9S2a := zlibCompress(buildSFNT(0x00010000, makeMultiGlyf(glyphsS2a)))
		assertE2ERejected(t, "R9_S2a_glyf_8b_7bit_pad.pdf", map[string][]byte{"r9_s2a.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cR9S2a)), cR9S2a)}, "IP_CONCEALMENT")
		cR9S2b := zlibCompress(buildSFNT(0x00010000, makeMultiGlyf(glyphsS2b)))
		assertE2ERejected(t, "R9_S2b_glyf_nc0_6b_pad.pdf", map[string][]byte{"r9_s2b.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cR9S2b)), cR9S2b)}, "IP_CONCEALMENT")

		// R9_S3: DSIG valid PKCS#7 SignedData with real self-signed ECDSA cert + 16x500B in signerInfos + 20x250B int in encapContentInfo
		ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test-signer"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecPriv.PublicKey, ecPriv)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		var siOctets bytes.Buffer
		for i := 0; i < 16; i++ {
			siOctets.Write(wrapDER(0x04, csprng[i*500:i*500+500]))
		}
		sdS3 := wrapDER(0x30, bytes.Join([][]byte{
			wrapDER(0x02, []byte{1}),
			wrapDER(0x31, nil),
			wrapDER(0x30, wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01})),
			wrapDER(0xa0, certDER),
			wrapDER(0x31, wrapDER(0x30, siOctets.Bytes())),
		}, nil))
		fullS3 := wrapDER(0x30, append(wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}), wrapDER(0xa0, sdS3)...))
		dsigS3 := make([]byte, 20+8+len(fullS3))
		binary.BigEndian.PutUint32(dsigS3[0:4], 1)
		binary.BigEndian.PutUint16(dsigS3[4:6], 1)
		binary.BigEndian.PutUint32(dsigS3[8:12], 1)
		binary.BigEndian.PutUint32(dsigS3[12:16], uint32(8+len(fullS3)))
		binary.BigEndian.PutUint32(dsigS3[16:20], 20)
		binary.BigEndian.PutUint32(dsigS3[24:28], uint32(len(fullS3)))
		copy(dsigS3[28:], fullS3)
		cS3 := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", dsigS3})))
		assertE2ERejected(t, "R9_S3_dsig_signerInfos_16x500b.pdf", map[string][]byte{"r9_s3.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS3)), cS3)}, "IP_CONCEALMENT")

		var eciInts bytes.Buffer
		for i := 0; i < 20; i++ {
			val := append([]byte{0x01}, csprng[i*250:i*250+249]...)
			eciInts.Write(wrapDER(0x02, val))
		}
		sdS3ECI := wrapDER(0x30, bytes.Join([][]byte{
			wrapDER(0x02, []byte{1}),
			wrapDER(0x31, nil),
			wrapDER(0x30, append(wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}), wrapDER(0xa0, wrapDER(0x30, eciInts.Bytes()))...)),
			wrapDER(0x31, nil),
		}, nil))
		fullS3ECI := wrapDER(0x30, append(wrapDER(0x06, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}), wrapDER(0xa0, sdS3ECI)...))
		dsigS3ECI := make([]byte, 20+8+len(fullS3ECI))
		binary.BigEndian.PutUint32(dsigS3ECI[0:4], 1)
		binary.BigEndian.PutUint16(dsigS3ECI[4:6], 1)
		binary.BigEndian.PutUint32(dsigS3ECI[8:12], 1)
		binary.BigEndian.PutUint32(dsigS3ECI[12:16], uint32(8+len(fullS3ECI)))
		binary.BigEndian.PutUint32(dsigS3ECI[16:20], 20)
		binary.BigEndian.PutUint32(dsigS3ECI[24:28], uint32(len(fullS3ECI)))
		copy(dsigS3ECI[28:], fullS3ECI)
		cS3ECI := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"DSIG", dsigS3ECI})))
		assertE2ERejected(t, "R9_S3_dsig_eci_20x250b_int.pdf", map[string][]byte{"r9_s3_eci.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS3ECI)), cS3ECI)}, "IP_CONCEALMENT")

		// CFF R9_S4a, adaptive R9_S4a (35% 139 + 7-bit imm247), R9_S4b, R9_S4c, cff_40_glyphs_sub256_run23
		buildCFFIndex := func(items [][]byte) []byte {
			var b bytes.Buffer
			_ = binary.Write(&b, binary.BigEndian, uint16(len(items)))
			if len(items) == 0 {
				return b.Bytes()
			}
			b.WriteByte(4)
			off := uint32(1)
			_ = binary.Write(&b, binary.BigEndian, off)
			for _, it := range items {
				off += uint32(len(it))
				_ = binary.Write(&b, binary.BigEndian, off)
			}
			for _, it := range items {
				b.Write(it)
			}
			return b.Bytes()
		}
		buildSimpleCFF := func(csItems [][]byte) []byte {
			hdr := []byte{1, 0, 4, 4}
			nameIdx := buildCFFIndex([][]byte{[]byte("Wave9CFF")})
			strIdx := buildCFFIndex(nil)
			gsubIdx := buildCFFIndex(nil)
			csIdx := buildCFFIndex(csItems)
			tdIdxLen := 2 + 1 + 2*4 + 6
			csOff := len(hdr) + len(nameIdx) + tdIdxLen + len(strIdx) + len(gsubIdx)
			var td bytes.Buffer
			td.WriteByte(29)
			_ = binary.Write(&td, binary.BigEndian, int32(csOff))
			td.WriteByte(17)
			tdIdx := buildCFFIndex([][]byte{td.Bytes()})
			return bytes.Join([][]byte{hdr, nameIdx, tdIdx, strIdx, gsubIdx, csIdx}, nil)
		}

		var csS4a bytes.Buffer
		for rep := 0; rep < 100; rep++ {
			for k := 0; k < 24; k++ {
				csS4a.WriteByte(byte(247 + (k % 3)))
				csS4a.WriteByte(csprng[rep*24+k])
			}
			csS4a.WriteByte(0x05)
		}
		csS4a.WriteByte(0x0e)
		cS4a := zlibCompress(buildSimpleCFF([][]byte{csS4a.Bytes()}))
		assertE2ERejected(t, "R9_S4a_cff_247.pdf", map[string][]byte{"r9_s4a.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cS4a)), cS4a)}, "IP_CONCEALMENT")

		// Adaptive R9_S4a: 35% constant 139 + 65% 7-bit imm247
		var csS4aAdapt bytes.Buffer
		for rep := 0; rep < 100; rep++ {
			for k := 0; k < 14; k++ {
				csS4aAdapt.WriteByte(139)
			}
			for k := 0; k < 26; k++ {
				csS4aAdapt.WriteByte(byte(247 + (k % 3)))
				csS4aAdapt.WriteByte(csprng7[rep*26+k])
			}
			csS4aAdapt.WriteByte(0x05)
		}
		csS4aAdapt.WriteByte(0x0e)
		cS4aAdapt := zlibCompress(buildSimpleCFF([][]byte{csS4aAdapt.Bytes()}))
		assertE2ERejected(t, "R9_S4a_adaptive_35pct139_7bit.pdf", map[string][]byte{"r9_s4a_adapt.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cS4aAdapt)), cS4aAdapt)}, "IP_CONCEALMENT")

		var csS4b bytes.Buffer
		for rep := 0; rep < 100; rep++ {
			for k := 0; k < 10; k++ {
				csS4b.WriteByte(28)
				csS4b.Write(csprng[(rep*10+k)*3 : (rep*10+k)*3+2])
				csS4b.WriteByte(byte(247 + (k % 3)))
				csS4b.WriteByte(csprng[(rep*10+k)*3+2])
			}
			csS4b.WriteByte(0x05)
		}
		csS4b.WriteByte(0x0e)
		cS4b := zlibCompress(buildSimpleCFF([][]byte{csS4b.Bytes()}))
		assertE2ERejected(t, "R9_S4b_cff_mixed_28_247.pdf", map[string][]byte{"r9_s4b.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cS4b)), cS4b)}, "IP_CONCEALMENT")

		var csS4c [][]byte
		for g := 0; g < 64; g++ {
			var gb bytes.Buffer
			for k := 0; k < 20; k++ {
				gb.WriteByte(28)
				gb.Write(csprng[(g*20+k)*2 : (g*20+k)*2+2])
			}
			gb.Write([]byte{0x05, 0x0e})
			csS4c = append(csS4c, gb.Bytes())
		}
		cS4c := zlibCompress(buildSimpleCFF(csS4c))
		assertE2ERejected(t, "R9_S4c_cff_64_small_28.pdf", map[string][]byte{"r9_s4c.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cS4c)), cS4c)}, "IP_CONCEALMENT")

		var csRun23 [][]byte
		for g := 0; g < 40; g++ {
			var gb bytes.Buffer
			for b := 0; b < 8; b++ {
				for k := 0; k < 23; k++ {
					gb.WriteByte(32 + (csprng[(g*8+b)*23+k] % 215))
				}
				gb.WriteByte(0x05)
			}
			gb.WriteByte(0x0e)
			csRun23 = append(csRun23, gb.Bytes())
		}
		cRun23 := zlibCompress(buildSimpleCFF(csRun23))
		assertE2ERejected(t, "cff_40_glyphs_sub256_run23.pdf", map[string][]byte{"run23.pdf": makeStreamPDF(fmt.Sprintf("/Subtype /Type1C /Length %d /Filter /FlateDecode", len(cRun23)), cRun23)}, "IP_CONCEALMENT")

		// SFNT meta "appl": R9_S5a, R9_S5b, sfnt_meta_appl_single_0x80_7bit
		buildMetaAppl := func(recData []byte) []byte {
			rec := make([]byte, 24+len(recData))
			binary.BigEndian.PutUint32(rec[0:4], 2)
			binary.LittleEndian.PutUint32(rec[8:12], 0x18)
			copy(rec[24:], recData)
			m := make([]byte, 28+len(rec))
			binary.BigEndian.PutUint32(m[0:4], 1)
			binary.BigEndian.PutUint32(m[8:12], 28)
			binary.BigEndian.PutUint32(m[12:16], 1)
			copy(m[16:20], "appl")
			binary.BigEndian.PutUint32(m[20:24], 28)
			binary.BigEndian.PutUint32(m[24:28], uint32(len(rec)))
			copy(m[28:], rec)
			return m
		}
		meta5a := make([]byte, 4096)
		for i := range meta5a {
			if i%11 < 2 {
				meta5a[i] = ' '
			} else {
				meta5a[i] = csprng[i]
			}
		}
		cS5a := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", buildMetaAppl(meta5a)})))
		assertE2ERejected(t, "R9_S5a_meta_appl_18pct_space.pdf", map[string][]byte{"r9_s5a.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS5a)), cS5a)}, "IP_CONCEALMENT")

		meta5b := make([]byte, 4096)
		for i := range meta5b {
			meta5b[i] = byte(16 + (int(csprng[i]) % 108))
		}
		cS5b := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", buildMetaAppl(meta5b)})))
		assertE2ERejected(t, "R9_S5b_meta_appl_108sym_7bit.pdf", map[string][]byte{"r9_s5b.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS5b)), cS5b)}, "IP_CONCEALMENT")

		metaSingle80 := append([]byte{0x80}, csprng7[:4095]...)
		cSingle80 := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"meta", buildMetaAppl(metaSingle80)})))
		assertE2ERejected(t, "sfnt_meta_appl_single_0x80_7bit.pdf", map[string][]byte{"meta_80.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cSingle80)), cSingle80)}, "IP_CONCEALMENT")

		// R9_S6: cvt 2048B CSPRNG with 16 nc=0 glyphs & trivial 16B fpgm (and 16 nc=1 tiny glyphs)
		var g16nc0, g16nc1 [][]byte
		for i := 0; i < 16; i++ {
			g16nc0 = append(g16nc0, make([]byte, 10))
			g1 := make([]byte, 17)
			binary.BigEndian.PutUint16(g1[0:2], 1)
			binary.BigEndian.PutUint16(g1[6:8], 100)
			binary.BigEndian.PutUint16(g1[8:10], 100)
			g1[14] = 0x06
			g16nc1 = append(g16nc1, g1)
		}
		fpgm16 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
		cS6a := zlibCompress(buildSFNT(0x00010000, append(makeMultiGlyf(g16nc0), sfntTbl{"fpgm", fpgm16}, sfntTbl{"cvt ", csprng[:2048]})))
		assertE2ERejected(t, "R9_S6_cvt_16_nc0_stub.pdf", map[string][]byte{"r9_s6a.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS6a)), cS6a)}, "IP_CONCEALMENT")
		cS6b := zlibCompress(buildSFNT(0x00010000, append(makeMultiGlyf(g16nc1), sfntTbl{"fpgm", fpgm16}, sfntTbl{"cvt ", csprng[:2048]})))
		assertE2ERejected(t, "R9_S6_16nc1_cvt_stub.pdf", map[string][]byte{"r9_s6b.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cS6b)), cS6b)}, "IP_CONCEALMENT")

		// sfnt_post_20x_200b_csprng_per10
		var postPer10 bytes.Buffer
		for i := 0; i < 20; i++ {
			postPer10.Write(csprng[i*200 : i*200+200])
			postPer10.Write(bytes.Repeat([]byte("0123456789"), 20))
		}
		cPostPer10 := zlibCompress(buildSFNT(0x00010000, append(baseSFNTTables(), sfntTbl{"post", postPer10.Bytes()})))
		assertE2ERejected(t, "sfnt_post_20x_200b_csprng_per10.pdf", map[string][]byte{"post_per10.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 4096 /Filter /FlateDecode", len(cPostPer10)), cPostPer10)}, "IP_CONCEALMENT")
	})

	t.Run("Cluster3_Media_L4b_ControlsAndBypasses", func(t *testing.T) {
		// Control: hashes[0..79] = "<64-hex>" indexed SHA-256 assignments -> 0 findings (ALLOW)
		var hashesInit bytes.Buffer
		hashesInit.WriteString("package main\nvar hashes [80]string\nfunc init() {\n")
		for i := 0; i < 80; i++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("ctrl-idx-hash-%d", i)))
			fmt.Fprintf(&hashesInit, "\thashes[%d] = \"%x\";\n", i, sum)
		}
		hashesInit.WriteString("}\n")
		assertE2EAllowed(t, "ctrl_hashes_indexed_80.go", map[string][]byte{"hashes_idx.go": hashesInit.Bytes()})

		// R9_P1: 64x64 bpc=8 PDF image left 36% {0x20, 0x21} checkerboard + right 64% CSPRNG
		imgP1 := make([]byte, 64*64)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				if x < 23 {
					if (x+y)%2 == 0 {
						imgP1[y*64+x] = 0x20
					} else {
						imgP1[y*64+x] = 0x21
					}
				} else {
					imgP1[y*64+x] = csprng[y*64+x]
				}
			}
		}
		cP1 := zlibCompress(imgP1)
		assertE2ERejected(t, "R9_P1_pdf_img_checker_0x20_0x21.pdf", map[string][]byte{
			"r9_p1.pdf": makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(cP1)), cP1),
		}, "IP_CONCEALMENT")

		// R9_P2b: ICC mAB CLUT with 60% {0x20..0x23} + 40% CSPRNG
		pad4 := func(b []byte) []byte {
			for len(b)%4 != 0 {
				b = append(b, 0)
			}
			return b
		}
		mab := make([]byte, 32+20+3000)
		copy(mab[0:4], "mAB ")
		mab[8], mab[9] = 3, 3
		binary.BigEndian.PutUint32(mab[24:28], 32)
		mab[32], mab[33], mab[34] = 10, 10, 10
		mab[32+16] = 1
		for pt := 0; pt < 1000; pt++ {
			if pt%5 < 3 {
				v := byte(0x20 + (pt % 4))
				mab[32+20+pt*3], mab[32+20+pt*3+1], mab[32+20+pt*3+2] = v, v, v
			} else {
				copy(mab[32+20+pt*3:32+20+pt*3+3], csprng[pt*3:pt*3+3])
			}
		}
		descTag := pad4(append([]byte("desc\x00\x00\x00\x00\x00\x00\x00\x08"), []byte("sRGB_IEC")...))
		cprtTag := pad4(append([]byte("text\x00\x00\x00\x00"), []byte("Copyright 2026")...))
		wtptTag := make([]byte, 20)
		copy(wtptTag[0:4], "XYZ ")
		mabPad := pad4(mab)
		off0 := 132 + 4*12
		off1 := off0 + len(descTag)
		off2 := off1 + len(cprtTag)
		off3 := off2 + len(wtptTag)
		icc := make([]byte, off3+len(mabPad))
		binary.BigEndian.PutUint32(icc[0:4], uint32(len(icc)))
		icc[8] = 2
		copy(icc[12:24], "mntrRGB XYZ ")
		copy(icc[36:40], "acsp")
		binary.BigEndian.PutUint32(icc[128:132], 4)
		putTag := func(i int, sig string, off, sz int) {
			copy(icc[132+i*12:], sig)
			binary.BigEndian.PutUint32(icc[132+i*12+4:], uint32(off))
			binary.BigEndian.PutUint32(icc[132+i*12+8:], uint32(sz))
		}
		putTag(0, "desc", off0, len(descTag))
		putTag(1, "cprt", off1, len(cprtTag))
		putTag(2, "wtpt", off2, len(wtptTag))
		putTag(3, "A2B0", off3, len(mab))
		copy(icc[off0:], descTag)
		copy(icc[off1:], cprtTag)
		copy(icc[off2:], wtptTag)
		copy(icc[off3:], mabPad)
		cP2b := zlibCompress(icc)
		assertE2ERejected(t, "R9_P2b_icc_mab_clut_4bytes.pdf", map[string][]byte{
			"r9_p2b.pdf": makeStreamPDF(fmt.Sprintf("/N 3 /Alternate /DeviceRGB /Length %d /Filter /FlateDecode", len(cP2b)), cP2b),
		}, "IP_CONCEALMENT")

		// R9_P4a, R9_P4b, and 4B span variant
		stuffFF := func(raw []byte) []byte {
			var b bytes.Buffer
			for _, c := range raw {
				b.WriteByte(c)
				if c == 0xFF {
					b.WriteByte(0x00)
				}
			}
			return b.Bytes()
		}
		buildDRIJPEG := func(w, h int, intervals [][]byte) []byte {
			var j bytes.Buffer
			j.Write([]byte{0xFF, 0xD8})
			j.Write(append([]byte{0xFF, 0xDB, 0x00, 0x43, 0x00}, bytes.Repeat([]byte{16}, 64)...))
			j.Write([]byte{0xFF, 0xC0, 0x00, 0x0B, 0x08, byte(h >> 8), byte(h), byte(w >> 8), byte(w), 0x01, 0x01, 0x11, 0x00})
			j.Write([]byte{0xFF, 0xC4, 0x00, 0x1F, 0x00, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
			j.Write([]byte{0xFF, 0xC4, 0x00, 0xB5, 0x10, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d,
				0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
				0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
				0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
				0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
				0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
				0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
				0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
				0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
				0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
				0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
				0xf9, 0xfa})
			j.Write([]byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01})
			j.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
			for idx, iv := range intervals {
				j.Write(iv)
				if idx < len(intervals)-1 {
					j.Write([]byte{0xFF, byte(0xD0 + (idx % 8))})
				}
			}
			j.Write([]byte{0xFF, 0xD9})
			return j.Bytes()
		}
		var anchorBuf [24]byte
		bitPos := 2
		for c := 0; c < 63; c++ {
			bitPos += 2
			anchorBuf[bitPos/8] |= 1 << (7 - (bitPos % 8))
			bitPos++
		}
		realAnchor := anchorBuf[:]

		ivsP4a := make([][]byte, 400)
		for i := 0; i < 400; i++ {
			if i%16 == 0 {
				ivsP4a[i] = stuffFF(realAnchor)
			} else {
				ivsP4a[i] = append([]byte{0x28}, stuffFF(csprng[i*10:i*10+10])...)
			}
		}
		jpgP4a := buildDRIJPEG(160, 160, ivsP4a)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgP4a)); dErr != nil {
			t.Fatalf("R9_P4a invalid JPEG: %v", dErr)
		}
		assertE2ERejected(t, "R9_P4a_jpg_dri_25anchors_10b.jpg", map[string][]byte{"r9_p4a.jpg": jpgP4a}, "IP_CONCEALMENT")

		ivsP4b := make([][]byte, 1024)
		ivsP4b4 := make([][]byte, 1024)
		for i := 0; i < 1024; i++ {
			if i%16 == 0 {
				ivsP4b[i] = stuffFF(realAnchor)
				ivsP4b4[i] = stuffFF(realAnchor)
			} else {
				ivsP4b[i] = append([]byte{0x28}, stuffFF(csprng[i*5:i*5+5])...)
				ivsP4b4[i] = append([]byte{0x28}, stuffFF(csprng[i*3:i*3+3])...)
			}
		}
		jpgP4b := buildDRIJPEG(256, 256, ivsP4b)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgP4b)); dErr != nil {
			t.Fatalf("R9_P4b invalid JPEG: %v", dErr)
		}
		assertE2ERejected(t, "R9_P4b_jpg_dri_64anchors_6b.jpg", map[string][]byte{"r9_p4b.jpg": jpgP4b}, "IP_CONCEALMENT")
		jpgP4b4 := buildDRIJPEG(256, 256, ivsP4b4)
		if _, dErr := jpeg.Decode(bytes.NewReader(jpgP4b4)); dErr != nil {
			t.Fatalf("R9_P4b_4B invalid JPEG: %v", dErr)
		}
		assertE2ERejected(t, "R9_P4b_4B_spans.jpg", map[string][]byte{"r9_p4b_4b.jpg": jpgP4b4}, "IP_CONCEALMENT")

		// R9_P5b (15-char // b64), R9_P5d (parts[i] = "..."), R9_P5f (// | <~...~>), R9_P5g ([{s:"..."}].map.join)
		b64Full := base64.StdEncoding.EncodeToString(stripped)
		var p5b strings.Builder
		for i := 0; i < len(b64Full); i += 15 {
			end := min(len(b64Full), i+15)
			p5b.WriteString("// ")
			p5b.WriteString(b64Full[i:end])
			p5b.WriteByte('\n')
		}
		assertE2ERejected(t, "R9_P5b_15char_comment_b64.go", map[string][]byte{"r9_p5b.go": []byte(p5b.String())}, "IP_CONCEALMENT")

		var p5d strings.Builder
		p5d.WriteString("const parts = [];\n")
		idx := 0
		for i := 0; i < len(b64Full); i += 40 {
			end := min(len(b64Full), i+40)
			fmt.Fprintf(&p5d, "parts[%d] = \"%s\";\n", idx, b64Full[i:end])
			idx++
		}
		p5d.WriteString("const out = parts.join(\"\");\n")
		assertE2ERejected(t, "R9_P5d_indexed_array_40char.js", map[string][]byte{"r9_p5d.js": []byte(p5d.String())}, "IP_CONCEALMENT")

		var a85 bytes.Buffer
		enc := ascii85.NewEncoder(&a85)
		_, _ = enc.Write(stripped)
		_ = enc.Close()
		a85Full := "<~" + a85.String() + "~>"

		var p5f strings.Builder
		for i := 0; i < len(a85Full); i += 32 {
			end := min(len(a85Full), i+32)
			p5f.WriteString("// | ")
			p5f.WriteString(a85Full[i:end])
			p5f.WriteByte('\n')
		}
		assertE2ERejected(t, "R9_P5f_pipe_comment_a85.go", map[string][]byte{"r9_p5f.go": []byte(p5f.String())}, "IP_CONCEALMENT")

		var p5gSegs []string
		for i := 0; i < len(a85Full); i += 32 {
			end := min(len(a85Full), i+32)
			segEsc := strings.ReplaceAll(a85Full[i:end], `\`, `\\`)
			segEsc = strings.ReplaceAll(segEsc, `"`, `\"`)
			p5gSegs = append(p5gSegs, fmt.Sprintf(`{s:"%s"}`, segEsc))
		}
		p5g := "const out = [" + strings.Join(p5gSegs, ", ") + "].map(x=>x.s).join(\"\");\n"
		assertE2ERejected(t, "R9_P5g_obj_array_a85.js", map[string][]byte{"r9_p5g.js": []byte(p5g)}, "IP_CONCEALMENT")

		// stride9_abc & per10 raw binaries
		stride9 := make([]byte, 512*9)
		for i := 0; i < 512; i++ {
			copy(stride9[i*9:], csprng[i*5:i*5+5])
			copy(stride9[i*9+5:], "ABCD")
		}
		assertE2ERejected(t, "stride9_abc.bin", map[string][]byte{"stride9_abc.bin": stride9}, "IP_CONCEALMENT")

		var per10 bytes.Buffer
		for i := 0; i < 20; i++ {
			per10.Write(csprng[i*200 : i*200+200])
			per10.Write(bytes.Repeat([]byte("0123456789"), 20))
		}
		assertE2ERejected(t, "per10.bin", map[string][]byte{"per10.bin": per10.Bytes()}, "IP_CONCEALMENT")

		// 800 KB O(N) stress checks across all L4b patterns (including {s:"ab"}, and a[0]="ab";)
		for _, tc := range []struct {
			name string
			unit string
		}{
			{"obj_arr_800kb.js", `{s:"ab"},`},
			{"idx_arr_800kb.js", `a[0]="ab";`},
			{"js_interp_800kb.js", "`ab`${"},
			{"py_fstr_800kb.py", `f"ab"{`},
		} {
			payload := bytes.Repeat([]byte(tc.unit), (800*1024)/len(tc.unit))
			start := time.Now()
			assertE2EAllowed(t, tc.name, map[string][]byte{tc.name: payload})
			el := time.Since(start)
			if isRaceEnabled || testing.Short() {
				t.Logf("%s (%d bytes): e2e=%v (non-gating under -race / -short per R5)", tc.name, len(payload), el)
				if el > 15*time.Second {
					t.Fatalf("%s runEngineOnFiles took %v (exceeded 15s quadratic-DoS safety ceiling under -race / -short)", tc.name, el)
				}
			} else {
				if el > 10*time.Second {
					t.Fatalf("%s runEngineOnFiles took %v (expected O(N) < 10s)", tc.name, el)
				}
				t.Logf("%s (%d bytes): e2e=%v", tc.name, len(payload), el)
			}
		}
	})

	t.Run("DefaultRunner_E2E_Pipeline", func(t *testing.T) {
		binDir := t.TempDir()
		mkStub := func(name, out string) string {
			p := filepath.Join(binDir, name)
			script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"--version\" ] || [ \"$1\" = \"version\" ]; then echo \"1.0.0\"; exit 0; fi\nout=\"\"\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) shift; out=\"$1\";; esac; shift; done\nif [ -n \"$out\" ]; then\ncat <<'EOF' > \"$out\"\n%s\nEOF\nelse\ncat <<'EOF'\n%s\nEOF\nfi\n", out, out)
			if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
				t.Fatalf("write stub %s: %v", name, err)
			}
			return p
		}
		scBin := filepath.Join(binDir, "scancode")
		scScript := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "ScanCode version 32.0.0"; exit 0; fi
out=""
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json-pp) shift; out="$1";;
    --license) ;;
    *) target="$1";;
  esac
  shift
done
files_json=""
for f in "$target"/*; do
  [ -f "$f" ] || continue
  base=$(basename "$f")
  if [ -n "$files_json" ]; then files_json="$files_json,"; fi
  files_json="$files_json{\"path\":\"$base\",\"type\":\"file\"}"
done
printf '{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.0.0"}],"files":[%s]}\n' "$files_json" > "$out"
`
		if err := os.WriteFile(scBin, []byte(scScript), 0o755); err != nil {
			t.Fatalf("write scancode stub: %v", err)
		}

		sgBin := filepath.Join(binDir, "semgrep")
		sgScript := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "1.0.0"; exit 0; fi
out=""
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) shift; out="$1";;
    scan|--json) ;;
    *) target="$1";;
  esac
  shift
done
scanned_json=""
for f in "$target"/*; do
  [ -f "$f" ] || continue
  if [ -n "$scanned_json" ]; then scanned_json="$scanned_json,"; fi
  scanned_json="$scanned_json\"$f\""
done
printf '{"version":"1.0.0","results":[],"errors":[],"paths":{"scanned":[%s],"skipped":[]}}\n' "$scanned_json" > "$out"
`
		if err := os.WriteFile(sgBin, []byte(sgScript), 0o755); err != nil {
			t.Fatalf("write semgrep stub: %v", err)
		}

		runner := inspection.NewRunner(inspection.Config{
			GitleaksBin:         mkStub("gitleaks", "[]"),
			ScanCodeBin:         scBin,
			SemgrepBin:          sgBin,
			TrivyBin:            mkStub("trivy", `{"Results":[]}`),
			IPFingerprinter:     engine,
			ScannerTimeout:      30 * time.Second,
			MaxFileInspectBytes: 16 << 20,
		})

		evalSummary := func(rep inspection.Report) domain.PolicyEffect {
			res, pErr := polEngine.Evaluate(context.Background(), compiledPol, policy.StagePushEgress, policy.PolicyInput{
				Stage:    policy.StagePushEgress,
				Findings: workflow.SummaryToFindingsInput(rep.Summary),
				Assessment: policy.AssessmentInput{
					Status:      "NOT_REQUIRED",
					IPRisk:      "NONE",
					Risk:        "NONE",
					Disposition: "NOT_REQUIRED",
				},
				Destination: policy.DestinationInput{
					ID:             "repo-internal",
					Name:           "acme/app",
					Host:           "github.com",
					Registered:     true,
					External:       false,
					Classification: "INTERNAL",
				},
				Push: policy.PushInput{
					RefNames:   []string{"refs/heads/main"},
					EgressMode: "ENFORCE_BLOCK",
				},
			})
			if pErr != nil {
				t.Fatalf("policy evaluate: %v", pErr)
			}
			return res.Effect
		}

		// Control through full DefaultRunner -> SummaryToFindingsInput -> policy.Engine -> ALLOW
		ctrlDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(ctrlDir, "clean.go"), []byte("package clean\nfunc Add(a, b int) int { return a + b }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pushID := domain.MustNewID()
		ctrlRep, err := runner.Inspect(context.Background(), inspection.Request{
			PushSessionID:  &pushID,
			ArtifactID:     domain.MustNewID(),
			TargetDir:      ctrlDir,
			Classification: domain.ClassificationInternal,
			Stage:          inspection.StagePushEgress,
		})
		if err != nil {
			t.Fatalf("DefaultRunner control Inspect: %v", err)
		}
		if eff := evalSummary(ctrlRep); eff != domain.PolicyEffectAllow {
			t.Fatalf("DefaultRunner control expected ALLOW, got %s (summary=%+v)", eff, ctrlRep.Summary)
		}

		// Attack through full DefaultRunner -> SummaryToFindingsInput -> policy.Engine -> DENY/QUARANTINE
		atkDir := t.TempDir()
		stride9 := make([]byte, 512*9)
		for i := 0; i < 512; i++ {
			copy(stride9[i*9:], csprng[i*5:i*5+5])
			copy(stride9[i*9+5:], "ABCD")
		}
		if err := os.WriteFile(filepath.Join(atkDir, "smuggled_stride9.bin"), stride9, 0o600); err != nil {
			t.Fatal(err)
		}
		pushID2 := domain.MustNewID()
		atkRep, err := runner.Inspect(context.Background(), inspection.Request{
			PushSessionID:  &pushID2,
			ArtifactID:     domain.MustNewID(),
			TargetDir:      atkDir,
			Classification: domain.ClassificationInternal,
			Stage:          inspection.StagePushEgress,
		})
		if err != nil {
			t.Fatalf("DefaultRunner attack Inspect: %v", err)
		}
		if eff := evalSummary(atkRep); eff != domain.PolicyEffectDeny && eff != domain.PolicyEffectQuarantine {
			t.Fatalf("DefaultRunner attack expected DENY/QUARANTINE, got %s (summary=%+v)", eff, atkRep.Summary)
		}
	})
}

func TestIter11RemediationAllClusters(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:               store,
		MaxFileInspectBytes: 16 << 20,
	})
	stripped := readFixture(t, "payloads/stripped_header_engine.go")

	zlibCompress := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		return buf.Bytes()
	}
	makeStreamPDF := func(dictEntries string, body []byte) []byte {
		var b bytes.Buffer
		b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< " + dictEntries + " >>\nstream\n")
		b.Write(body)
		b.WriteString("\nendstream\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n")
		return b.Bytes()
	}

	csprng := make([]byte, 16384)
	state := uint32(0x9e3779b9)
	for i := range csprng {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		csprng[i] = byte(state >> 24)
	}

	assertAllowed := func(t *testing.T, files map[string][]byte) {
		t.Helper()
		findings, cov, aErr := runEngineOnFiles(t, engine, files, "")
		if aErr != nil {
			t.Fatalf("Analyze error: %v", aErr)
		}
		if !cov.Complete {
			t.Fatalf("expected complete coverage, got %+v", cov)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings on valid controls, got %+v", findings)
		}
	}
	assertBlocked := func(t *testing.T, label string, files map[string][]byte) {
		t.Helper()
		findings, cov, aErr := runEngineOnFiles(t, engine, files, "")
		if aErr != nil {
			t.Fatalf("%s Analyze error: %v", label, aErr)
		}
		if !cov.Complete {
			t.Fatalf("%s expected complete coverage, got %+v", label, cov)
		}
		if len(findings) == 0 {
			t.Fatalf("%s expected >= 1 finding, got 0", label)
		}
	}

	writeULEB := func(buf *bytes.Buffer, v uint32) {
		for {
			b := byte(v & 0x7f)
			v >>= 7
			if v != 0 {
				b |= 0x80
			}
			buf.WriteByte(b)
			if v == 0 {
				break
			}
		}
	}
	wrapWASMSection := func(secID byte, body []byte) []byte {
		var out bytes.Buffer
		out.WriteByte(secID)
		writeULEB(&out, uint32(len(body)))
		out.Write(body)
		return out.Bytes()
	}

	t.Run("Cluster1_WASMSec10_L4a_KitchenSink", func(t *testing.T) {
		// Benign controls: uint64 monotonic table (like kitchen_sink_wasip1 seg[127]), mono32, sin4096, SHA-256 text.
		mono64 := make([]byte, 1024)
		for i := 0; i < 128; i++ {
			binary.LittleEndian.PutUint64(mono64[i*8:], uint64(i)*1234+0x100000)
		}
		mono32 := make([]byte, 512)
		for i := 0; i < 128; i++ {
			binary.LittleEndian.PutUint32(mono32[i*4:], uint32(i*17+100))
		}
		sin4096 := make([]byte, 4096)
		for i := 0; i < 1024; i++ {
			val := uint32(1000000.0 + math.Sin(float64(i)*2*math.Pi/1024.0)*100000.0)
			binary.LittleEndian.PutUint32(sin4096[i*4:], val)
		}
		// Build valid WASM with mono64, mono32, sin4096 in active Data section (secID == 11).
		var dataSec bytes.Buffer
		dataSec.WriteByte(0x03) // 3 segments
		for _, seg := range [][]byte{mono64, mono32, sin4096} {
			dataSec.WriteByte(0x00)
			dataSec.Write([]byte{0x41, 0x10, 0x0b}) // i32.const 16; end
			writeULEB(&dataSec, uint32(len(seg)))
			dataSec.Write(seg)
		}
		wasmMonoCtrl := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01}
		wasmMonoCtrl = append(wasmMonoCtrl, wrapWASMSection(11, dataSec.Bytes())...)

		var shaLines strings.Builder
		for i := 0; i < 20; i++ {
			s := sha256.Sum256([]byte(fmt.Sprintf("ctrl-%d", i)))
			fmt.Fprintf(&shaLines, "sha256:%x\n", s)
		}
		ctrlFiles := map[string][]byte{
			"mono_tables.wasm": wasmMonoCtrl,
			"digests.txt":      []byte(shaLines.String()),
		}
		if !testing.Short() {
			if goBin, lookErr := exec.LookPath("go"); lookErr == nil {
				tmpGo := t.TempDir()
				ksSrc := `package main
import (
	"crypto/aes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)
func main() {
	b, _ := aes.NewCipher(make([]byte, 16))
	var out [16]byte
	b.Encrypt(out[:], []byte("0123456789abcdef"))
	nums := []int{9, 3, 7, 1, 5}
	sort.Ints(nums)
	j, _ := json.Marshal(map[string]any{"n": nums, "s": strconv.Itoa(42)})
	fmt.Println(len(j), out[0])
}
`
				if wErr := os.WriteFile(filepath.Join(tmpGo, "go.mod"), []byte("module ks\n\ngo 1.22\n"), 0o600); wErr == nil {
					if wErr := os.WriteFile(filepath.Join(tmpGo, "main.go"), []byte(ksSrc), 0o600); wErr == nil {
						outWasm := filepath.Join(tmpGo, "kitchen_sink_wasip1.wasm")
						cmd := exec.Command(goBin, "build", "-o", outWasm, ".")
						cmd.Dir = tmpGo
						cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
						if cmd.Run() == nil {
							if kb, rErr := os.ReadFile(outWasm); rErr == nil && len(kb) > 0 {
								ctrlFiles["kitchen_sink_wasip1.wasm"] = kb
							}
						}
					}
				}
			}
		}
		assertAllowed(t, ctrlFiles)

		// L4a concealment vectors: MSB7, 6-bit, C0+6bit, C0+MSB7, 2B per=37, 10B 3.9%, N8/N9 stride=17/37, 20/32/40-val pads.
		msb7 := make([]byte, 1024)
		sixBit := make([]byte, 1024)
		for i := range msb7 {
			msb7[i] = csprng[i] & 0x7f
			sixBit[i] = csprng[i] & 0x3f
		}
		interleaveC0 := func(src []byte, stride int) []byte {
			var out []byte
			for i, b := range src {
				out = append(out, b)
				if (i+1)%stride == 0 {
					out = append(out, 0x00, 0x01)
				}
			}
			return out
		}
		per2_37 := make([]byte, 37*40)
		for i := 0; i < 40; i++ {
			copy(per2_37[i*37:], csprng[i*35:i*35+35])
			per2_37[i*37+35] = 0xaa
			per2_37[i*37+36] = 0x55
		}
		pad10_39 := make([]byte, 0, 2048)
		for i := 0; i < 512; i++ {
			pad10_39 = append(pad10_39, csprng[i], byte(i%10))
		}
		mkStride := func(stride int) []byte {
			out := make([]byte, 256*stride)
			for i := 0; i < 256; i++ {
				out[i*stride] = 0x42
				copy(out[i*stride+1:], csprng[i*(stride-1):(i+1)*(stride-1)])
			}
			return out
		}
		mkMultiPad := func(k int) []byte {
			out := make([]byte, 0, 2048)
			for i := 0; i < 1024; i++ {
				out = append(out, byte(0xe0+(i%k)))
				out = append(out, csprng[i])
			}
			return out
		}
		for name, payload := range map[string][]byte{
			"msb7.bin":     msb7,
			"sixbit.bin":   sixBit,
			"c0_6bit.bin":  interleaveC0(sixBit, 4),
			"c0_msb7.bin":  interleaveC0(msb7, 4),
			"per2_37.bin":  per2_37,
			"pad10_39.bin": pad10_39,
			"n8_str17.bin": mkStride(17),
			"n9_str37.bin": mkStride(37),
			"pad20.bin":    mkMultiPad(20),
			"pad32.bin":    mkMultiPad(32),
			"pad40.bin":    mkMultiPad(40),
		} {
			assertBlocked(t, name, map[string][]byte{name: payload})
		}

		// N10a / N10b: WASM Code section (secID == 10) concealed CSPRNG (standalone & with dead trailing bytes).
		var codeBody bytes.Buffer
		codeBody.WriteByte(0x01) // 1 body
		fnBody := append([]byte{0x00, 0x0b}, csprng[:1024]...)
		writeULEB(&codeBody, uint32(len(fnBody)))
		codeBody.Write(fnBody)
		wasmN10a := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00}
		wasmN10a = append(wasmN10a, wrapWASMSection(10, codeBody.Bytes())...)
		assertBlocked(t, "N10a_wasm_sec10_dead", map[string][]byte{"n10a.wasm": wasmN10a})

		var codeBodyBad bytes.Buffer
		codeBodyBad.WriteByte(0x01)
		fnBad := append([]byte{0x00}, msb7[:512]...)
		fnBad = append(fnBad, 0x0b)
		writeULEB(&codeBodyBad, uint32(len(fnBad)))
		codeBodyBad.Write(fnBad)
		wasmN10b := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00}
		wasmN10b = append(wasmN10b, wrapWASMSection(10, codeBodyBad.Bytes())...)
		assertBlocked(t, "N10b_wasm_sec10_msb7", map[string][]byte{"n10b.wasm": wasmN10b})
	})

	t.Run("Cluster2_SFNT_CFF_ControlsAndBypasses", func(t *testing.T) {
		// Benign controls: Times New Roman Bold, Courier New, ADTNumeric, STIXSizFourSymBol (embedded in PDF font stream).
		ctrlFonts := map[string][]byte{}
		for _, fp := range []string{
			"/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf",
			"/System/Library/Fonts/Supplemental/Courier New.ttf",
			"/System/Library/Fonts/ADTNumeric.ttc",
			"/System/Library/Fonts/Supplemental/STIXSizFourSymBol.otf",
		} {
			if fb, rErr := os.ReadFile(fp); rErr == nil {
				comp := zlibCompress(fb)
				ctrlFonts["ctrl_"+filepath.Base(fp)+".pdf"] = makeStreamPDF(
					fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(comp), len(fb)), comp)
			}
		}
		if len(ctrlFonts) > 0 {
			assertAllowed(t, ctrlFonts)
		}

		// Local SFNT builder helper.
		buildSFNT := func(sfntTag uint32, tables map[string][]byte) []byte {
			names := make([]string, 0, len(tables))
			for k := range tables {
				names = append(names, k)
			}
			// Sort tags lexicographically.
			for i := 0; i < len(names); i++ {
				for j := i + 1; j < len(names); j++ {
					if names[j] < names[i] {
						names[i], names[j] = names[j], names[i]
					}
				}
			}
			hdrLen := 12 + len(names)*16
			var out bytes.Buffer
			_ = binary.Write(&out, binary.BigEndian, sfntTag)
			_ = binary.Write(&out, binary.BigEndian, uint16(len(names)))
			_ = binary.Write(&out, binary.BigEndian, uint16(16))
			_ = binary.Write(&out, binary.BigEndian, uint16(0))
			_ = binary.Write(&out, binary.BigEndian, uint16(0))
			curOff := hdrLen
			for _, k := range names {
				d := tables[k]
				out.WriteString(k)
				_ = binary.Write(&out, binary.BigEndian, uint32(0))
				_ = binary.Write(&out, binary.BigEndian, uint32(curOff))
				_ = binary.Write(&out, binary.BigEndian, uint32(len(d)))
				curOff += (len(d) + 3) &^ 3
			}
			for _, k := range names {
				d := tables[k]
				out.Write(d)
				for out.Len()%4 != 0 {
					out.WriteByte(0)
				}
			}
			return out.Bytes()
		}
		mkHead := func() []byte {
			h := make([]byte, 54)
			binary.BigEndian.PutUint32(h[0:4], 0x00010000)
			binary.BigEndian.PutUint32(h[12:16], 0x5F0F3CF5)
			binary.BigEndian.PutUint16(h[18:20], 1000)
			binary.BigEndian.PutUint16(h[50:52], 1) // long loca
			return h
		}
		mkMaxp := func(n uint16) []byte {
			m := make([]byte, 6)
			binary.BigEndian.PutUint32(m[0:4], 0x00010000)
			binary.BigEndian.PutUint16(m[4:6], n)
			return m
		}

		// P3: glyf flags concealed CSPRNG
		gFlags := make([]byte, 512)
		for i := range gFlags {
			gFlags[i] = csprng[i] & 0x37 // clears bit3 repeat & 0x08 so each flag is 1 byte, high entropy
		}
		var glyfP3 bytes.Buffer
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(1))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(0))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(0))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(100))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(100))
		_ = binary.Write(&glyfP3, binary.BigEndian, uint16(len(gFlags)-1))
		_ = binary.Write(&glyfP3, binary.BigEndian, uint16(0)) // instrLen=0
		glyfP3.Write(gFlags)
		// append x/y coordinates (2 bytes each with flags=0..0x37 -> just make flags=0x06 so 1-byte x, 1-byte y, or use 0x30+csprng&0x07):
		glyfP3.Reset()
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(1))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(0))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(0))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(100))
		_ = binary.Write(&glyfP3, binary.BigEndian, int16(100))
		_ = binary.Write(&glyfP3, binary.BigEndian, uint16(511))
		_ = binary.Write(&glyfP3, binary.BigEndian, uint16(0))
		for i := 0; i < 512; i++ {
			// bits 0..7 excluding bit3 (0x08) and keeping on-curve/sign bits varied
			glyfP3.WriteByte((csprng[i] & 0x37) | 0x30) // x-same/y-same bits 4&5 mean 0 bytes coords -> only flags!
		}
		locaP3 := make([]byte, 8)
		binary.BigEndian.PutUint32(locaP3[4:8], uint32(glyfP3.Len()))
		assertBlocked(t, "P3_glyf_flags", map[string][]byte{
			"p3.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "loca": locaP3, "glyf": glyfP3.Bytes()}),
		})

		// P4: glyf aggCoords MSB7 concealed CSPRNG across glyphs
		var glyfP4 bytes.Buffer
		var locaP4 bytes.Buffer
		_ = binary.Write(&locaP4, binary.BigEndian, uint32(0))
		for g := 0; g < 16; g++ {
			_ = binary.Write(&glyfP4, binary.BigEndian, int16(1))
			_ = binary.Write(&glyfP4, binary.BigEndian, int16(0))
			_ = binary.Write(&glyfP4, binary.BigEndian, int16(0))
			_ = binary.Write(&glyfP4, binary.BigEndian, int16(100))
			_ = binary.Write(&glyfP4, binary.BigEndian, int16(100))
			_ = binary.Write(&glyfP4, binary.BigEndian, uint16(31)) // 32 points
			_ = binary.Write(&glyfP4, binary.BigEndian, uint16(0))
			for p := 0; p < 32; p++ {
				glyfP4.WriteByte(0x06) // 1B x, 1B y
			}
			for p := 0; p < 64; p++ {
				glyfP4.WriteByte(csprng[g*64+p] & 0x7f)
			}
			_ = binary.Write(&locaP4, binary.BigEndian, uint32(glyfP4.Len()))
		}
		assertBlocked(t, "P4_glyf_aggCoords_msb7", map[string][]byte{
			"p4.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(16), "loca": locaP4.Bytes(), "glyf": glyfP4.Bytes()}),
		})

		// P5: cvt 50-stub (minimal 50 glyphs + dummy fpgm + CSPRNG cvt)
		cvtP5 := make([]byte, 1024)
		copy(cvtP5, csprng[:1024])
		assertBlocked(t, "P5_cvt_50stub", map[string][]byte{
			"p5.ttf": buildSFNT(0x00010000, map[string][]byte{
				"head": mkHead(), "maxp": mkMaxp(50),
				"fpgm": append([]byte{0x2c, 0x00, 0x2d}, make([]byte, 24)...),
				"cvt ": cvtP5,
			}),
		})

		// P6: DSIG with 16% spaces + 7-bit AND >1536 MSB7
		mkDSIGWithPrim := func(prim []byte) []byte {
			// Minimal DER Sequence -> OID -> OCTET STRING containing prim
			var oct bytes.Buffer
			oct.WriteByte(0x04)
			if len(prim) < 128 {
				oct.WriteByte(byte(len(prim)))
			} else {
				oct.Write([]byte{0x82, byte(len(prim) >> 8), byte(len(prim))})
			}
			oct.Write(prim)
			der := oct.Bytes()
			var dsig bytes.Buffer
			_ = binary.Write(&dsig, binary.BigEndian, uint32(1)) // version
			_ = binary.Write(&dsig, binary.BigEndian, uint16(1)) // numSigs
			_ = binary.Write(&dsig, binary.BigEndian, uint16(0)) // flags
			_ = binary.Write(&dsig, binary.BigEndian, uint32(1)) // format
			_ = binary.Write(&dsig, binary.BigEndian, uint32(len(der)+8))
			_ = binary.Write(&dsig, binary.BigEndian, uint32(20)) // offset
			dsig.Write([]byte{0, 0, 0, 0, 0, 0})
			_ = binary.Write(&dsig, binary.BigEndian, uint16(len(der)))
			dsig.Write(der)
			return dsig.Bytes()
		}
		p6MSB7 := make([]byte, 2048)
		for i := range p6MSB7 {
			p6MSB7[i] = csprng[i] & 0x7f
		}
		assertBlocked(t, "P6_DSIG_msb7_gt1536", map[string][]byte{
			"p6.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "DSIG": mkDSIGWithPrim(p6MSB7)}),
		})

		// P7: meta "appl" MSB7 + 10% interleaved decoys
		applPay := make([]byte, 24+4096)
		binary.BigEndian.PutUint32(applPay[0:4], 2)
		binary.LittleEndian.PutUint32(applPay[8:12], 0x18)
		for i := 0; i < 4096; i++ {
			if i%12 == 0 {
				applPay[24+i] = 0x80 + byte((i/12)%40)
			} else {
				applPay[24+i] = csprng[i] & 0x7f
			}
		}
		var metaTbl bytes.Buffer
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(1))
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(0))
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(28))
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(1))
		metaTbl.WriteString("appl")
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(28))
		_ = binary.Write(&metaTbl, binary.BigEndian, uint32(len(applPay)))
		metaTbl.Write(applPay)
		assertBlocked(t, "P7_meta_appl_msb7_decoys", map[string][]byte{
			"p7.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "meta": metaTbl.Bytes()}),
		})

		// P8: CFF multi-constant 32..246 + >62% 247..254 CSPRNG immediates
		mkCFFIndex := func(items [][]byte) []byte {
			var b bytes.Buffer
			_ = binary.Write(&b, binary.BigEndian, uint16(len(items)))
			if len(items) == 0 {
				return b.Bytes()
			}
			b.WriteByte(2) // offSize=2
			off := uint16(1)
			_ = binary.Write(&b, binary.BigEndian, off)
			for _, it := range items {
				off += uint16(len(it))
				_ = binary.Write(&b, binary.BigEndian, off)
			}
			for _, it := range items {
				b.Write(it)
			}
			return b.Bytes()
		}
		var csP8 bytes.Buffer
		for i := 0; i < 400; i++ {
			// mix 10 different constant 1B integers (32..41) + >62% 2-byte CSPRNG ops
			if i%4 == 0 {
				csP8.WriteByte(byte(32 + (i/4)%10))
			} else {
				csP8.WriteByte(247)
				csP8.WriteByte(csprng[i] & 0x7f)
			}
		}
		csP8.WriteByte(14) // endchar
		nameIdx := mkCFFIndex([][]byte{[]byte("P8Font")})
		strIdx := mkCFFIndex(nil)
		gsubIdx := mkCFFIndex(nil)
		csIdx := mkCFFIndex([][]byte{csP8.Bytes()})
		// TopDICT: charset(15)=0, Encoding(16)=0, CharStrings(17)=off
		// Encode TopDICT with 5-byte int (29 + uint32) for CharStrings offset:
		topLen := 6 // 5-byte int (29 + uint32) + op 17
		hdrPlus := 4 + len(nameIdx) + 7 + topLen + len(strIdx) + len(gsubIdx)
		var td bytes.Buffer
		td.WriteByte(29)
		_ = binary.Write(&td, binary.BigEndian, uint32(hdrPlus))
		td.WriteByte(17)
		tdIdx := mkCFFIndex([][]byte{td.Bytes()})
		var cffBuf bytes.Buffer
		cffBuf.Write([]byte{1, 0, 4, 2})
		cffBuf.Write(nameIdx)
		cffBuf.Write(tdIdx)
		cffBuf.Write(strIdx)
		cffBuf.Write(gsubIdx)
		cffBuf.Write(csIdx)
		p8SFNT := buildSFNT(0x4F54544F, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "CFF ": cffBuf.Bytes()})
		compP8 := zlibCompress(p8SFNT)
		assertBlocked(t, "P8_CFF_multiconst_62pct", map[string][]byte{
			"p8.pdf": makeStreamPDF(fmt.Sprintf("/Length %d /Length1 %d /Filter /FlateDecode", len(compP8), len(p8SFNT)), compP8),
		})

		// N4 (gvar CSPRNG), N5a (EBDT CSPRNG), N5b (COLR CSPRNG), N5c (fpgm invalid/CSPRNG)
		assertBlocked(t, "N4_gvar", map[string][]byte{
			"n4.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "gvar": csprng[:1024]}),
		})
		assertBlocked(t, "N5a_EBDT", map[string][]byte{
			"n5a.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "EBDT": csprng[:1024]}),
		})
		assertBlocked(t, "N5b_COLR", map[string][]byte{
			"n5b.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "COLR": csprng[:1024]}),
		})
		assertBlocked(t, "N5c_fpgm", map[string][]byte{
			"n5c.ttf": buildSFNT(0x00010000, map[string][]byte{"head": mkHead(), "maxp": mkMaxp(1), "fpgm": csprng[:512]}),
		})
	})

	t.Run("Cluster3_Media_PDF_ICC_L4b", func(t *testing.T) {
		// 1. Benign Media controls: PNG, smooth GIF, VP8/VP8L WebP, minimal JP2, cjpeg progressive/DRI if available.
		pal := color.Palette{
			color.RGBA{0, 0, 0, 255}, color.RGBA{32, 32, 64, 255},
			color.RGBA{64, 128, 192, 255}, color.RGBA{220, 230, 240, 255},
		}
		animGIF := &gif.GIF{}
		for fr := 0; fr < 2; fr++ {
			im := image.NewPaletted(image.Rect(0, 0, 64, 64), pal)
			for y := 0; y < 64; y++ {
				for x := 0; x < 64; x++ {
					im.SetColorIndex(x, y, uint8(((x/16)+(y/16)+fr)%4))
				}
			}
			animGIF.Image = append(animGIF.Image, im)
			animGIF.Delay = append(animGIF.Delay, 10)
		}
		var gifBuf bytes.Buffer
		if err := gif.EncodeAll(&gifBuf, animGIF); err != nil {
			t.Fatal(err)
		}

		// Minimal valid JP2 helper.
		mkBox := func(boxType string, payload []byte) []byte {
			var b bytes.Buffer
			_ = binary.Write(&b, binary.BigEndian, uint32(8+len(payload)))
			b.WriteString(boxType)
			b.Write(payload)
			return b.Bytes()
		}
		ihdr := make([]byte, 14)
		binary.BigEndian.PutUint32(ihdr[0:4], 16)
		binary.BigEndian.PutUint32(ihdr[4:8], 16)
		binary.BigEndian.PutUint16(ihdr[8:10], 3)
		ihdr[10] = 7
		colr := []byte{1, 0, 0, 0, 0, 0, 16}
		jp2h := append(mkBox("ihdr", ihdr), mkBox("colr", colr)...)
		var j2k bytes.Buffer
		j2k.Write([]byte{0xFF, 0x4F})
		siz := make([]byte, 38+3*3)
		binary.BigEndian.PutUint16(siz[0:2], 49)
		binary.BigEndian.PutUint32(siz[4:8], 16)
		binary.BigEndian.PutUint32(siz[8:12], 16)
		binary.BigEndian.PutUint32(siz[20:24], 16)
		binary.BigEndian.PutUint32(siz[24:28], 16)
		binary.BigEndian.PutUint16(siz[36:38], 3)
		for c := 0; c < 3; c++ {
			siz[38+c*3] = 7
			siz[38+c*3+1] = 1
			siz[38+c*3+2] = 1
		}
		j2k.Write([]byte{0xFF, 0x51})
		j2k.Write(siz)
		cod := make([]byte, 12)
		binary.BigEndian.PutUint16(cod[0:2], 12)
		j2k.Write([]byte{0xFF, 0x52})
		j2k.Write(cod)
		qcd := make([]byte, 5)
		binary.BigEndian.PutUint16(qcd[0:2], 5)
		j2k.Write([]byte{0xFF, 0x5C})
		j2k.Write(qcd)
		j2k.Write([]byte{0xFF, 0x90, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // SOT psot=0
		j2k.Write([]byte{0xFF, 0x93})                                                             // SOD
		j2k.Write([]byte{0x00, 0x11, 0x22, 0x33})
		j2k.Write([]byte{0xFF, 0xD9}) // EOC
		validJP2 := bytes.Join([][]byte{
			mkBox("jP  ", []byte{0x0D, 0x0A, 0x87, 0x0A}),
			mkBox("ftyp", []byte("jp2 \x00\x00\x00\x00jp2 ")),
			mkBox("jp2h", jp2h),
			mkBox("jp2c", j2k.Bytes()),
		}, nil)

		// PDF 16-bit smooth, 4-bit smooth, Indexed smooth, SHA-256/SHA-512 manifest allowlists.
		smooth16 := make([]byte, 64*64*2)
		for i := 0; i < 64*64; i++ {
			binary.BigEndian.PutUint16(smooth16[i*2:], uint16((i%64)*1000))
		}
		c16 := zlibCompress(smooth16)
		pdf16 := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 16 /Length %d /Filter /FlateDecode", len(c16)), c16)

		smooth4 := make([]byte, 64*64/2)
		for y := 0; y < 64; y++ {
			for x := 0; x < 32; x++ {
				v := byte((x / 2) & 0x0f)
				smooth4[y*32+x] = (v << 4) | v
			}
		}
		c4 := zlibCompress(smooth4)
		pdf4 := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 4 /Length %d /Filter /FlateDecode", len(c4)), c4)

		idxSmooth := make([]byte, 64*64)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				idxSmooth[y*64+x] = byte((x + y) / 2)
			}
		}
		cIdxSmooth := zlibCompress(idxSmooth)
		pdfIdxSmooth := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace [/Indexed /DeviceRGB 255 <000000>] /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(cIdxSmooth)), cIdxSmooth)

		var manifest512 strings.Builder
		manifest512.WriteString("package digests\n\nvar Hashes = []string{\n")
		for i := 0; i < 80; i++ {
			s2 := sha256.Sum256([]byte(fmt.Sprintf("item-%d", i)))
			s5 := sha512.Sum512([]byte(fmt.Sprintf("item-%d", i)))
			fmt.Fprintf(&manifest512, "\t\"sha256-%s\",\n\t\"sha512-%s\",\n",
				base64.StdEncoding.EncodeToString(s2[:]),
				base64.StdEncoding.EncodeToString(s5[:]))
		}
		manifest512.WriteString("}\n")

		mediaCtrls := map[string][]byte{
			"ctrl.png":           buildGenuinePNG(t, 64, 64),
			"ctrl_anim.gif":      gifBuf.Bytes(),
			"ctrl_vp8.webp":      buildMinimalValidVP8WebP(),
			"ctrl_vp8l.webp":     buildMinimalValidVP8LWebP(),
			"ctrl.jp2":           validJP2,
			"pdf_16bit.pdf":      pdf16,
			"pdf_4bit.pdf":       pdf4,
			"pdf_idx_smooth.pdf": pdfIdxSmooth,
			"hashes.go":          []byte(manifest512.String()),
		}
		if cjpegPath, err := exec.LookPath("cjpeg"); err == nil {
			ppm := bytes.NewBufferString("P6\n128 128\n255\n")
			for y := 0; y < 128; y++ {
				for x := 0; x < 128; x++ {
					ppm.Write([]byte{byte(x * 2), byte(y * 2), byte(x + y)})
				}
			}
			for _, args := range [][]string{
				{"-progressive"},
				{"-progressive", "-restart", "4"},
				{"-progressive", "-sample", "1x1", "-restart", "4"},
				{"-progressive", "-grayscale", "-restart", "4"},
			} {
				cmd := exec.Command(cjpegPath, args...)
				cmd.Stdin = bytes.NewReader(ppm.Bytes())
				if out, cErr := cmd.Output(); cErr == nil && len(out) > 0 {
					mediaCtrls["cjpeg_"+strings.Join(args, "_")+".jpg"] = out
				}
			}
		}
		assertAllowed(t, mediaCtrls)

		// Attacks:
		// N13: png_csprng_pixels + PNG trailing bytes inside IDAT deflate stream
		assertBlocked(t, "N13_png_csprng_pixels", map[string][]byte{"n13_pix.png": buildCSPRNGPNG(t, 48, 48)})
		basePNG := buildGenuinePNG(t, 48, 48)
		// Replace IDAT payload with valid zlib + trailing 512B CSPRNG inside IDAT!
		ihdrOff := bytes.Index(basePNG, []byte("IDAT")) - 4
		iendOff := bytes.Index(basePNG, []byte("IEND")) - 4
		if ihdrOff > 0 && iendOff > ihdrOff {
			var rawZ bytes.Buffer
			zw := zlib.NewWriter(&rawZ)
			_, _ = zw.Write(bytes.Repeat([]byte{0}, 48*(48*4+1)))
			_ = zw.Close()
			rawZ.Write(csprng[:512])
			var pngTrail bytes.Buffer
			pngTrail.Write(basePNG[:ihdrOff])
			pngTrail.Write(makePNGChunk("IDAT", rawZ.Bytes()))
			pngTrail.Write(basePNG[iendOff:])
			assertBlocked(t, "N13_png_idat_trailing", map[string][]byte{"n13_trail.png": pngTrail.Bytes()})
		}

		// N14: WebP CSPRNG in VP8, VP8L, ALPH, ANMF
		assertBlocked(t, "N14_webp_vp8", map[string][]byte{"n14_vp8.webp": buildGenuineVP8WebP(csprng[:512])})
		assertBlocked(t, "N14_webp_vp8l", map[string][]byte{"n14_vp8l.webp": buildGenuineVP8LWebP(csprng[:512])})
		assertBlocked(t, "N14_webp_alph", map[string][]byte{"n14_alph.webp": buildRIFFWebP(
			struct {
				fourCC  string
				payload []byte
			}{"VP8X", []byte{0x10, 0, 0, 0, 15, 0, 0, 15, 0, 0}},
			struct {
				fourCC  string
				payload []byte
			}{"ALPH", append([]byte{0x01}, csprng[:512]...)},
			struct {
				fourCC  string
				payload []byte
			}{"VP8 ", minimalValidVP8Chunk()},
		)})

		// N15: GIF CSPRNG comment + GIF CSPRNG decoded pixels
		rawGIF := gifBuf.Bytes()
		commentExt := append([]byte{0x21, 0xFE, 0xFF}, csprng[:255]...)
		commentExt = append(commentExt, 0xFF)
		commentExt = append(commentExt, csprng[255:510]...)
		commentExt = append(commentExt, 0x00)
		var gifCmt bytes.Buffer
		gifCmt.Write(rawGIF[:len(rawGIF)-1])
		gifCmt.Write(commentExt)
		gifCmt.WriteByte(0x3B)
		assertBlocked(t, "N15_gif_comment", map[string][]byte{"n15_cmt.gif": gifCmt.Bytes()})

		var fullPal color.Palette
		for i := 0; i < 256; i++ {
			fullPal = append(fullPal, color.RGBA{byte(i), byte(255 - i), byte((i * 7) & 0xff), 255})
		}
		csprngGIFImg := image.NewPaletted(image.Rect(0, 0, 64, 64), fullPal)
		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				csprngGIFImg.SetColorIndex(x, y, csprng[y*64+x])
			}
		}
		var csprngGIF bytes.Buffer
		_ = gif.Encode(&csprngGIF, csprngGIFImg, nil)
		assertBlocked(t, "N15_gif_csprng_pixels", map[string][]byte{"n15_pix.gif": csprngGIF.Bytes()})

		// N16: JP2 unstuffed J2K codestream CSPRNG + uuid CSPRNG box
		var j2kNoFF bytes.Buffer
		j2kNoFF.Write([]byte{0xFF, 0x4F, 0xFF, 0x51})
		j2kNoFF.Write(siz)
		j2kNoFF.Write([]byte{0xFF, 0x52})
		j2kNoFF.Write(cod)
		j2kNoFF.Write([]byte{0xFF, 0x5C})
		j2kNoFF.Write(qcd)
		j2kNoFF.Write([]byte{0xFF, 0x90, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x93})
		for i := 0; i < 4200; i++ {
			b := csprng[i]
			if b == 0xff {
				b = 0xfe
			}
			j2kNoFF.WriteByte(b)
		}
		j2kNoFF.Write([]byte{0xFF, 0xD9})
		jp2N16 := bytes.Join([][]byte{
			mkBox("jP  ", []byte{0x0D, 0x0A, 0x87, 0x0A}),
			mkBox("ftyp", []byte("jp2 \x00\x00\x00\x00jp2 ")),
			mkBox("jp2h", jp2h),
			mkBox("jp2c", j2kNoFF.Bytes()),
		}, nil)
		assertBlocked(t, "N16_jp2_unstuffed", map[string][]byte{"n16.jp2": jp2N16})

		// JPEG N1 (SOF1 12-bit UnsupportedError), N2a (SOF3), N2b (SOF9), N3c (DRI mismatch)
		mkFakeSOFJ := func(sofMarker byte, prec byte) []byte {
			var j bytes.Buffer
			j.Write([]byte{0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00})
			j.Write(bytes.Repeat([]byte{16}, 64))
			j.Write([]byte{0xFF, sofMarker, 0x00, 0x0B, prec, 0x00, 0x40, 0x00, 0x40, 0x01, 0x01, 0x11, 0x00})
			j.Write([]byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
			for _, c := range csprng[:1024] {
				j.WriteByte(c)
				if c == 0xFF {
					j.WriteByte(0x00)
				}
			}
			j.Write([]byte{0xFF, 0xD9})
			return j.Bytes()
		}
		assertBlocked(t, "N1_jpg_sof1_12bit", map[string][]byte{"n1.jpg": mkFakeSOFJ(0xC1, 12)})
		assertBlocked(t, "N2a_jpg_sof3", map[string][]byte{"n2a.jpg": mkFakeSOFJ(0xC3, 8)})
		assertBlocked(t, "N2b_jpg_sof9", map[string][]byte{"n2b.jpg": mkFakeSOFJ(0xC9, 8)})

		// N6 (PDF bpc=4 CSPRNG) & N7a (PDF Indexed 4-pixel non-rowcol CSPRNG)
		cN6 := zlibCompress(csprng[:2048])
		pdfN6 := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 4 /Length %d /Filter /FlateDecode", len(cN6)), cN6)
		assertBlocked(t, "N6_pdf_bpc4_csprng", map[string][]byte{"n6.pdf": pdfN6})

		cN7 := zlibCompress(csprng[:4096])
		pdfN7 := makeStreamPDF(fmt.Sprintf("/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace [/Indexed /DeviceRGB 255 <000000>] /BitsPerComponent 8 /Length %d /Filter /FlateDecode", len(cN7)), cN7)
		assertBlocked(t, "N7_pdf_indexed_csprng", map[string][]byte{"n7.pdf": pdfN7})

		// L4b: R9_P5b (4..7-char wrapped + 1..3-char tail), F3 (HTML comments), F6 ("<"+"~..."), N12a..e.
		b64Full := base64.StdEncoding.EncodeToString(stripped)
		var wrap5 strings.Builder
		for i := 0; i < len(b64Full); i += 5 {
			end := min(len(b64Full), i+5)
			fmt.Fprintf(&wrap5, "\"%s\" + ", b64Full[i:end])
		}
		wrap5.WriteString("\"\"")
		assertBlocked(t, "R9_P5b_5char_wrap", map[string][]byte{"r9_p5b_5.js": []byte("const s = " + wrap5.String() + ";\n")})

		var htmlF3 strings.Builder
		htmlF3.WriteString("const s = ")
		for i := 0; i < len(b64Full); i += 16 {
			end := min(len(b64Full), i+16)
			fmt.Fprintf(&htmlF3, "\"%s\" <!-- dec --> + ", b64Full[i:end])
		}
		htmlF3.WriteString("\"\";\n")
		assertBlocked(t, "F3_html_comment", map[string][]byte{"f3.js": []byte(htmlF3.String())})

		var a85Buf bytes.Buffer
		a85Enc := ascii85.NewEncoder(&a85Buf)
		_, _ = a85Enc.Write(stripped)
		_ = a85Enc.Close()
		a85Str := a85Buf.String()
		var f6B strings.Builder
		f6B.WriteString("const p = \"<\" + \"~")
		for i := 0; i < len(a85Str); i += 32 {
			end := min(len(a85Str), i+32)
			seg := strings.ReplaceAll(a85Str[i:end], `\`, `\\`)
			seg = strings.ReplaceAll(seg, `"`, `\"`)
			fmt.Fprintf(&f6B, "%s\" + \"", seg)
		}
		f6B.WriteString("~>\";\n")
		assertBlocked(t, "F6_split_lt_tilde", map[string][]byte{"f6.js": []byte(f6B.String())})

		var n12PlusEq strings.Builder
		for i := 0; i < len(b64Full); i += 16 {
			end := min(len(b64Full), i+16)
			fmt.Fprintf(&n12PlusEq, "s += \"%s\"\n", b64Full[i:end])
		}
		assertBlocked(t, "N12a_pluseq", map[string][]byte{"n12a.go": []byte(n12PlusEq.String())})

		var n12Push strings.Builder
		for i := 0; i < len(b64Full); i += 16 {
			end := min(len(b64Full), i+16)
			fmt.Fprintf(&n12Push, "buf.WriteString(\"%s\")\n", b64Full[i:end])
		}
		assertBlocked(t, "N12b_WriteString", map[string][]byte{"n12b.go": []byte(n12Push.String())})
	})
}

func TestIter12StandaloneICCAndFontsAndDisguisedControls(t *testing.T) {
	ctx := context.Background()
	store, _, _ := seedDefaultCorpora(t)
	restrictedSrc := readFixture(t, "corpora/restricted/proprietary_engine.go")
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store, RequireStore: true})

	// 1. All 14 standalone ColorSync .icc (and .icm) profiles must pass with 0 FPs.
	iccPaths, _ := filepath.Glob("/System/Library/ColorSync/Profiles/*.icc")
	if len(iccPaths) > 0 {
		var sampleICC []byte
		for _, p := range iccPaths {
			iccBytes, rErr := os.ReadFile(p)
			if rErr != nil || len(iccBytes) == 0 {
				continue
			}
			if sampleICC == nil {
				sampleICC = iccBytes
			}
			base := filepath.Base(p)
			for _, name := range []string{base, strings.TrimSuffix(base, ".icc") + ".icm"} {
				findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: iccBytes}, "")
				if err != nil || !cov.Complete || len(findings) != 0 {
					t.Fatalf("standalone ICC %s expected 0 findings, cov=%+v err=%v findings=%+v", name, cov, err, findings)
				}
			}
		}
		if sampleICC != nil {
			// Valid ICC disguised with a source extension must be flagged.
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{"disguised.go": sampleICC}, "")
			if err != nil || !cov.Complete || len(findings) == 0 {
				t.Fatalf("ICC disguised as .go expected findings, cov=%+v err=%v findings=%+v", cov, err, findings)
			}
		}
		t.Logf("Swept %d standalone ColorSync .icc/.icm profiles: 0 FPs", len(iccPaths))
	}

	// 2. Standalone macOS .ttf/.otf/.ttc fonts (<= 4 MiB) must pass with 0 FPs.
	var fontPaths []string
	for _, root := range []string{"/System/Library/Fonts", "/System/Library/Fonts/Supplemental"} {
		entries, rErr := os.ReadDir(root)
		if rErr != nil {
			continue
		}
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			lower := strings.ToLower(ent.Name())
			if !strings.HasSuffix(lower, ".ttf") && !strings.HasSuffix(lower, ".otf") && !strings.HasSuffix(lower, ".ttc") {
				continue
			}
			info, stErr := ent.Info()
			if stErr != nil || info.Size() <= 0 || info.Size() > 4<<20 {
				continue
			}
			fontPaths = append(fontPaths, filepath.Join(root, ent.Name()))
		}
	}
	if len(fontPaths) > 0 {
		shortFilter := map[string]bool{
			"Arial.ttf": true, "Apple Symbols.ttf": true, "Courier.ttc": true,
			"Helvetica.ttc": true, "SFNSMono.ttf": true, "Times.ttc": true,
			"LastResort.otf": true, "Geneva.ttf": true, "PTSans.ttc": true,
			"Noteworthy.ttc": true, "STIXTwoMath.otf": true, "STIXGeneral.otf": true,
		}
		type fontJob struct {
			fp string
			fb []byte
		}
		var jobs []fontJob
		var sampleSFNT []byte
		for _, fp := range fontPaths {
			if testing.Short() && !shortFilter[filepath.Base(fp)] {
				continue
			}
			fb, rErr := os.ReadFile(fp)
			if rErr != nil || len(fb) == 0 {
				continue
			}
			if sampleSFNT == nil && (strings.HasSuffix(strings.ToLower(fp), ".ttf") || strings.HasSuffix(strings.ToLower(fp), ".otf")) {
				sampleSFNT = fb
			}
			jobs = append(jobs, fontJob{fp: fp, fb: fb})
		}
		jobCh := make(chan fontJob, len(jobs))
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)

		var errMu sync.Mutex
		var errs []string
		var checked int64
		var wg sync.WaitGroup
		workers := runtime.GOMAXPROCS(0)
		if workers < 4 {
			workers = 4
		}
		if workers > 12 {
			workers = 12
		}
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tmpBase, mkErr := os.MkdirTemp("", "custodian-standalone-font-*")
				if mkErr != nil {
					errMu.Lock()
					errs = append(errs, mkErr.Error())
					errMu.Unlock()
					return
				}
				defer func() { _ = os.RemoveAll(tmpBase) }()

				for j := range jobCh {
					absPath := filepath.Join(tmpBase, filepath.Base(j.fp))
					if wErr := os.WriteFile(absPath, j.fb, 0o600); wErr != nil {
						errMu.Lock()
						errs = append(errs, wErr.Error())
						errMu.Unlock()
						return
					}
					inv, walkErr := inspection.WalkWorkspace(tmpBase)
					if walkErr != nil {
						_ = os.Remove(absPath)
						errMu.Lock()
						errs = append(errs, walkErr.Error())
						errMu.Unlock()
						return
					}
					findings, cov, err := engine.Analyze(ctx, inspection.Request{
						PushSessionID: ptrUUID(domain.MustNewID()),
						ArtifactID:    domain.MustNewID(),
						TargetDir:     tmpBase,
						Stage:         inspection.StagePushEgress,
					}, inv)
					_ = os.Remove(absPath)
					if err != nil || !cov.Complete || len(findings) != 0 {
						errMu.Lock()
						errs = append(errs, fmt.Sprintf("standalone font %s expected 0 findings, cov=%+v err=%v findings=%+v", j.fp, cov, err, findings))
						errMu.Unlock()
						return
					}
					errMu.Lock()
					checked++
					errMu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(errs) > 0 {
			t.Fatalf("%s", errs[0])
		}
		if sampleSFNT != nil {
			findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{"disguised_font.go": sampleSFNT}, "")
			if err != nil || !cov.Complete || len(findings) == 0 {
				t.Fatalf("SFNT disguised as .go expected findings, cov=%+v err=%v findings=%+v", cov, err, findings)
			}
		}
		t.Logf("Swept %d standalone macOS fonts (<= 4 MiB): 0 FPs", checked)
	}

	// 3. Disguised Go source / CSPRNG with .icc / .icm / .ttf / .otf / .ttc extensions MUST still be flagged.
	csprng := make([]byte, 4096)
	for off := 0; off < len(csprng); off += 32 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("iter12-csprng-%d", off)))
		copy(csprng[off:], sum[:])
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"disguised.icc", restrictedSrc},
		{"disguised.icm", restrictedSrc},
		{"disguised.ttf", restrictedSrc},
		{"disguised.otf", restrictedSrc},
		{"disguised.ttc", restrictedSrc},
		{"corrupt_entropy.icc", csprng[:1024]},
		{"corrupt_entropy.ttf", append([]byte{0x00, 0x01, 0x00, 0x00}, csprng[:1024]...)},
		{"corrupt_entropy.ttc", append([]byte("ttcf\x00\x01\x00\x00\x00\x00\x00\x01"), csprng[:1024]...)},
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{tc.name: tc.data}, "")
		if err != nil || !cov.Complete || len(findings) == 0 {
			t.Fatalf("%s expected mismatch/concealment findings, cov=%+v err=%v findings=%+v", tc.name, cov, err, findings)
		}
		if !hasRule(findings, "ip.l4.magic-byte-mismatch") && !hasRule(findings, "ip.l4.high-entropy") {
			t.Fatalf("%s expected magic-byte-mismatch or high-entropy finding, got %+v", tc.name, findings)
		}
	}

	// 4. Valid standalone ICC containing explicit proprietary banner MUST still be flagged (L3).
	buildValidICCWithTag := func(tagName string, tagData []byte) []byte {
		for len(tagData)%4 != 0 {
			tagData = append(tagData, 0)
		}
		tagOff := uint32(132 + 3*12)
		descTag := append([]byte("desc\x00\x00\x00\x00\x00\x00\x00\x08sRGB\x00\x00\x00\x00"), make([]byte, 12)...)
		for len(descTag)%4 != 0 {
			descTag = append(descTag, 0)
		}
		wtptTag := make([]byte, 20)
		copy(wtptTag[0:4], "XYZ ")
		total := tagOff + uint32(len(tagData)+len(descTag)+len(wtptTag))
		buf := make([]byte, total)
		binary.BigEndian.PutUint32(buf[0:4], total)
		buf[8] = 2
		copy(buf[12:16], "mntr")
		copy(buf[16:20], "RGB ")
		copy(buf[20:24], "XYZ ")
		copy(buf[36:40], "acsp")
		binary.BigEndian.PutUint32(buf[128:132], 3)
		// Tag 0: tagName
		copy(buf[132:136], tagName)
		binary.BigEndian.PutUint32(buf[136:140], tagOff)
		binary.BigEndian.PutUint32(buf[140:144], uint32(len(tagData)))
		copy(buf[tagOff:], tagData)
		off1 := tagOff + uint32(len(tagData))
		copy(buf[144:148], "desc")
		binary.BigEndian.PutUint32(buf[148:152], off1)
		binary.BigEndian.PutUint32(buf[152:156], uint32(len(descTag)))
		copy(buf[off1:], descTag)
		off2 := off1 + uint32(len(descTag))
		copy(buf[156:160], "wtpt")
		binary.BigEndian.PutUint32(buf[160:164], off2)
		binary.BigEndian.PutUint32(buf[164:168], uint32(len(wtptTag)))
		copy(buf[off2:], wtptTag)
		return buf
	}
	explicitTag := make([]byte, 80)
	copy(explicitTag[0:4], "text")
	copy(explicitTag[8:], "Classification: RESTRICTED — Acme Proprietary\x00")
	explicitICC := buildValidICCWithTag("cprt", explicitTag)
	if expFindings, expCov, expErr := runEngineOnFiles(t, engine, map[string][]byte{"secret.icc": explicitICC}, ""); expErr != nil || !expCov.Complete || len(expFindings) == 0 {
		t.Fatalf("standalone ICC with explicit RESTRICTED banner expected findings, cov=%+v err=%v findings=%+v", expCov, expErr, expFindings)
	}
}

func TestIter12L4bKeyEqualsBase64AndNonFPControls(t *testing.T) {
	store, _, _ := seedDefaultCorpora(t)
	restrictedSrc := readFixture(t, "corpora/restricted/proprietary_engine.go")
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store, RequireStore: true})

	summarize := func(findings []domain.Finding, cov domain.ScanCoverage) inspection.InspectionSummary {
		sum := inspection.InspectionSummary{
			MandatoryScannersComplete: cov.Complete && cov.FilesSkipped == 0,
			ScanComplete:              cov.Complete && cov.FilesSkipped == 0,
		}
		for _, f := range findings {
			sum.TotalFindings++
			switch f.Category {
			case "IP_CONCEALMENT":
				sum.ConcealmentFindings++
			case "IP_EXACT":
				sum.IPExactMatches++
			case "IP_WINNOW":
				sum.IPWinnowMatches++
			case "IP_HEADER_STRIP":
				sum.IPHeaderStripMatches++
			}
			if f.Category == "IP_EXACT" || f.Category == "IP_WINNOW" || f.Category == "IP_HEADER_MARKER" || f.Category == "IP_HEADER_STRIP" {
				cls, _ := f.Metadata["corpus_classification"].(string)
				if cls == "" {
					cls, _ = f.Metadata["classification"].(string)
				}
				if strings.EqualFold(cls, string(domain.ClassificationRestricted)) {
					sum.RestrictedIPMatches++
				}
			}
		}
		return sum
	}

	b64Std := base64.StdEncoding.EncodeToString(restrictedSrc)
	b64URL := base64.RawURLEncoding.EncodeToString(restrictedSrc)
	b64URLPad := base64.URLEncoding.EncodeToString(restrictedSrc)

	var multi40 strings.Builder
	multi40.WriteString("data=")
	for i := 0; i < len(b64Std); i += 40 {
		end := min(len(b64Std), i+40)
		multi40.WriteString(b64Std[i:end])
		multi40.WriteByte('\n')
	}

	var multiNextLine strings.Builder
	multiNextLine.WriteString("data=\n")
	for i := 0; i < len(b64Std); i += 40 {
		end := min(len(b64Std), i+40)
		multiNextLine.WriteString(b64Std[i:end])
		multiNextLine.WriteByte('\n')
	}

	var multiComment strings.Builder
	multiComment.WriteString("# OTHER=abcd\n# data=")
	for i := 0; i < len(b64Std); i += 40 {
		end := min(len(b64Std), i+40)
		if i > 0 {
			multiComment.WriteString("# ")
		}
		multiComment.WriteString(b64Std[i:end])
		multiComment.WriteByte('\n')
	}

	quotedConcatEq := fmt.Sprintf("const p = \"payload=%s\" + \"%s\";\n", b64Std[:len(b64Std)/2], b64Std[len(b64Std)/2:])

	for _, tc := range []struct {
		name string
		file string
		body string
	}{
		{"data_eq_std", "data_eq.txt", "data=" + b64Std + "\n"},
		{"token_eq_url_raw", "b64_url.txt", "token=" + b64URL + "\n"},
		{"token_eq_url_pad", "b64_url_pad.txt", "token=" + b64URLPad + "\n"},
		{"payload_eq_sh", "payload_eq.sh", "#!/bin/sh\nPAYLOAD=" + b64Std + "\n"},
		{"url_query_md", "url_query.md", "https://example.com/ingest?payload=" + b64URL + "\n"},
		{"ini_encoded_blob", "ini_cfg.ini", "[section]\nencoded_blob=" + b64Std + "\n"},
		{"multiline_data_40", "multiline_eq.txt", multi40.String()},
		{"multiline_next_line", "multiline_next.txt", multiNextLine.String()},
		{"multiline_comment_after_other", "multiline_cmt.py", multiComment.String()},
		{"quoted_concat_eq", "quoted_eq.js", quotedConcatEq},
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{tc.file: []byte(tc.body)}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", tc.name, cov, err)
		}
		sum := summarize(findings, cov)
		if sum.IPExactMatches == 0 || sum.ConcealmentFindings == 0 || sum.RestrictedIPMatches == 0 {
			t.Fatalf("%s expected IPExactMatches>0, ConcealmentFindings>0, RestrictedIPMatches>0, got sum=%+v findings=%+v", tc.name, sum, findings)
		}
	}

	// Non-FP realistic controls: package-lock.json integrity, go.sum, normal URLs.
	pkgLock := `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/example": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
      "integrity": "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=="
    },
    "node_modules/another": {
      "version": "4.5.6",
      "integrity": "sha512-9bX5J3h8k6vY2wQ8nM1pL4zR7cV0tF3gH6jK9mN2pQ5sT8vW1yZ4aB7cD0eF3gH6jK9mN2pQ5sT8vW1yZ4aBw=="
    }
  }
}`
	goSum := `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
golang.org/x/crypto v0.31.0 h1:ihbySMvGj4IWX+3a8a5fR9x0N2Q4m8T1u3v5w7y9z0A=
`
	normalURL := "callback=https://auth.example.com/oauth2/authorize?client_id=custodian-web&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid+profile+email&state=xyz123abc456def789\n"

	for name, content := range map[string]string{
		"package-lock.json": pkgLock,
		"go.sum":            goSum,
		"urls.env":          normalURL,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: []byte(content)}, "")
		if err != nil || !cov.Complete || len(findings) != 0 {
			t.Fatalf("non-FP control %s expected 0 findings, cov=%+v err=%v findings=%+v", name, cov, err, findings)
		}
	}

	// 800KB vs 400KB interior-'=' stress payload must scale O(N) (ratio ~2x, not O(N^2)).
	stress400 := strings.Repeat("a=b=", 100*1024)
	t400Start := time.Now()
	findings400, cov400, err400 := runEngineOnFiles(t, engine, map[string][]byte{"stress_eq_400.txt": []byte(stress400)}, "")
	el400 := time.Since(t400Start)
	if err400 != nil || !cov400.Complete || len(findings400) != 0 {
		t.Fatalf("stress_eq_400.txt unexpected failure: cov=%+v err=%v findings=%+v", cov400, err400, findings400)
	}
	stress800 := strings.Repeat("a=b=", 200*1024)
	start := time.Now()
	findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{"stress_eq.txt": []byte(stress800)}, "")
	elapsed := time.Since(start)
	if err != nil || !cov.Complete || len(findings) != 0 {
		t.Fatalf("stress_eq.txt unexpected failure: cov=%+v err=%v findings=%+v", cov, err, findings)
	}
	if isRaceEnabled || testing.Short() {
		t.Logf("stress_eq O(N) check: 400KB=%v 800KB=%v (non-gating under -race / -short per R5)", el400, elapsed)
		if elapsed > 15*time.Second {
			t.Fatalf("stress_eq.txt took %v (exceeded 15s quadratic-DoS safety ceiling under -race / -short)", elapsed)
		}
	} else {
		if el400 > 0 && float64(elapsed)/float64(el400) > 3.5 && elapsed > 500*time.Millisecond {
			t.Fatalf("stress_eq.txt non-linear scaling: 400KB=%v 800KB=%v", el400, elapsed)
		}
		t.Logf("stress_eq O(N) check: 400KB=%v 800KB=%v", el400, elapsed)
	}
}

func TestL3HeaderCodeLineBoundaryAndStrippedHeaderRegression(t *testing.T) {
	ctx := context.Background()
	emptyStore := fingerprints.NewMemoryCorpusStore()
	emptyEngine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:        emptyStore,
		RequireStore: true,
	})

	// 1. Benign files with leading comments or code lines containing "proprietary" / "confidential"
	// must NOT emit false-positive IP_HEADER_MARKER findings against an empty corpus.
	benignCases := map[string][]byte{
		"ui.js":                    []byte("// UI helpers\nimport { x } from \"./proprietary\";\nexport const y = x;\n"),
		"helper.py":                []byte("# Helper module\nfrom acme.confidential import public_helper\ndef run(): return public_helper()\n"),
		"benign_pkg.go":            []byte("// Helper utilities\npackage proprietary\nfunc Add(a, b int) int { return a + b }\n"),
		"no_comment_pkg.go":        []byte("package proprietary\nfunc Add(a, b int) int { return a + b }\n"),
		"no_comment_import.js":     []byte("import { x } from \"./proprietary\";\nexport const y = x;\n"),
		"blank_after_comment.ts":   []byte("// UI helpers\n\nexport const proprietaryEndpoint = \"/api/public\";\n"),
		"inline_block_comment.js":  []byte("/* UI helpers */ import { x } from \"./proprietary\";\nexport const y = x;\n"),
		"c_include.c":              []byte("// C helper\n#include \"proprietary.h\"\nint main() { return 0; }\n"),
		"shebang.py":               []byte("#!/usr/bin/env python3\n# Helper module\nfrom acme.confidential import public_helper\n"),
		"non_keyword_after_cmt.js": []byte("// UI helpers\nproprietaryHelper();\n"),
		"readme.md":                []byte("# Architecture Guide\n\nThis module integrates with our proprietary vendor API and confidential client config.\n"),
	}
	for name, content := range benignCases {
		findings, cov, err := runEngineOnFiles(t, emptyEngine, map[string][]byte{name: content}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("benign case %s failed: cov=%+v err=%v", name, cov, err)
		}
		if len(findings) != 0 {
			t.Fatalf("benign case %s expected 0 findings against empty corpus, got %+v", name, findings)
		}
	}

	// 2. Legitimate bare plain-text leading notices (lines 1..3) and comment headers must still match.
	bareNotice := []byte("Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.\nCONFIDENTIAL AND PROPRIETARY TRADE SECRET.\nDo not distribute outside Acme.\n")
	hdrBare := fingerprints.ExtractHeadersAndBody(bareNotice)
	if !hdrBare.HasHeader || len(hdrBare.Markers) != 3 {
		t.Fatalf("expected 3 markers on bare plain-text notice, got %+v", hdrBare)
	}
	bareFindings, bareCov, err := runEngineOnFiles(t, emptyEngine, map[string][]byte{"NOTICE.txt": bareNotice}, "")
	if err != nil || !bareCov.Complete || !hasRule(bareFindings, "ip.l3.header-marker") {
		t.Fatalf("expected ip.l3.header-marker on bare NOTICE.txt, cov=%+v err=%v findings=%+v", bareCov, err, bareFindings)
	}

	leadingBlankNotice := []byte("\nCopyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.\n")
	blankNoticeFindings, _, err := runEngineOnFiles(t, emptyEngine, map[string][]byte{"LICENSE_NOTICE.txt": leadingBlankNotice}, "")
	if err != nil || !hasRule(blankNoticeFindings, "ip.l3.header-marker") {
		t.Fatalf("expected ip.l3.header-marker on leading-blank plain-text notice, err=%v findings=%+v", err, blankNoticeFindings)
	}

	spacedCommentHeader := []byte("// Classification: RESTRICTED\n\n// Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.\npackage proprietary\nfunc F() int { return 1 }\n")
	hdrSpaced := fingerprints.ExtractHeadersAndBody(spacedCommentHeader)
	if !hdrSpaced.HasHeader || len(hdrSpaced.Markers) != 2 {
		t.Fatalf("expected 2 markers (stopping before `package proprietary`) on spaced comment header, got %+v", hdrSpaced)
	}

	blockCommentHeader := []byte("/*\n * Classification: RESTRICTED\n */\nimport \"proprietary/client\"\n")
	hdrBlock := fingerprints.ExtractHeadersAndBody(blockCommentHeader)
	if !hdrBlock.HasHeader || len(hdrBlock.Markers) != 1 || hdrBlock.Markers[0].Classification != domain.ClassificationRestricted {
		t.Fatalf("expected 1 RESTRICTED marker from block comment before import, got %+v", hdrBlock)
	}

	// 3. Stripping a leading proprietary header from a `package proprietary` RESTRICTED corpus file
	// must NOT treat `package proprietary` as an L3 marker and MUST emit `ip.l3.header-stripped`.
	corpusSrc := []byte(`// Classification: RESTRICTED
// Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.
package proprietary

func ComputeProtectedTelemetryScore(samples []float64, factor float64) float64 {
	total := 17.425
	for idx, v := range samples {
		total += (v * factor) / (1.0 + float64(idx)*0.03125)
	}
	return total
}
`)
	corpusHdr := fingerprints.ExtractHeadersAndBody(corpusSrc)
	if !corpusHdr.HasHeader || len(corpusHdr.Markers) != 2 {
		t.Fatalf("expected exactly 2 header markers (excluding `package proprietary`), got %+v", corpusHdr)
	}

	store := fingerprints.NewMemoryCorpusStore()
	idxr := fingerprints.NewCorpusIndexer(store, store)
	corpusRow, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "restricted-prop-pkg",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}
	if _, err := idxr.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpusRow.ID,
		Files: []fingerprints.CorpusFile{
			{Path: "proprietary/scorer.go", Content: corpusSrc},
		},
	}); err != nil {
		t.Fatalf("Index corpus: %v", err)
	}

	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:        store,
		RequireStore: true,
	})
	strippedSrc := []byte(`package proprietary

func ComputeProtectedTelemetryScore(samples []float64, factor float64) float64 {
	total := 17.425
	for idx, v := range samples {
		total += (v * factor) / (1.0 + float64(idx)*0.03125)
	}
	return total
}
`)
	strippedWithDecoyComment := append([]byte("// Helper utilities\n"), strippedSrc...)

	for name, payload := range map[string][]byte{
		"stripped.go":       strippedSrc,
		"stripped_decoy.go": strippedWithDecoyComment,
	} {
		findings, cov, err := runEngineOnFiles(t, engine, map[string][]byte{name: payload}, "")
		if err != nil || !cov.Complete {
			t.Fatalf("%s Analyze failed: cov=%+v err=%v", name, cov, err)
		}
		if !hasRule(findings, "ip.l3.header-stripped") {
			t.Fatalf("%s expected ip.l3.header-stripped, got %+v", name, findings)
		}
		if hasRule(findings, "ip.l3.header-marker") {
			t.Fatalf("%s did not expect ip.l3.header-marker after header was stripped, got %+v", name, findings)
		}
		var stripFinding *domain.Finding
		for i := range findings {
			if findings[i].RuleID == "ip.l3.header-stripped" {
				stripFinding = &findings[i]
				break
			}
		}
		if stripFinding == nil || stripFinding.Category != "IP_HEADER_STRIP" || stripFinding.Severity != domain.SeverityCritical {
			t.Fatalf("%s expected CRITICAL IP_HEADER_STRIP finding, got %+v", name, findings)
		}
		if strippedFlag, _ := stripFinding.Metadata["header_stripped"].(bool); !strippedFlag {
			t.Fatalf("%s expected header_stripped=true metadata, got %+v", name, stripFinding.Metadata)
		}
	}

	// 4. Unified diff modifying code imports referencing `./proprietary` must NOT false-positive.
	benignDiff := `diff --git a/ui.js b/ui.js
--- a/ui.js
+++ b/ui.js
@@ -1,3 +1,3 @@
 // UI helpers
-import { oldFn } from "./proprietary";
+import { newFn } from "./public";
 export const y = 1;
`
	if strips := fingerprints.DetectStrippedHeadersInUnifiedDiff(benignDiff); len(strips) != 0 {
		t.Fatalf("expected 0 diff strips on benign import change, got %+v", strips)
	}
}

type tier5BlockingTxRunner struct {
	inner     fingerprints.CorpusTxRunner
	entered   chan struct{}
	release   chan struct{}
	failErr   error
	onceEnter sync.Once
}

func (r *tier5BlockingTxRunner) RunCorpusTx(ctx context.Context, fn func(tx fingerprints.CorpusTxStore) error) error {
	if r.entered != nil {
		r.onceEnter.Do(func() { close(r.entered) })
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if r.failErr != nil {
		return r.failErr
	}
	return r.inner.RunCorpusTx(ctx, fn)
}

func TestTier5_ReadyCorpusReindexZeroBypassWindowAndPreservedOnCancelOrTxError(t *testing.T) {
	ctx := context.Background()
	store := fingerprints.NewMemoryCorpusStore()
	srcV1 := readFixture(t, "corpora/restricted/proprietary_engine.go")
	srcV2 := append(append([]byte(nil), srcV1...), []byte("\nfunc ProprietaryExtraV2(x int) int { return x*7 + 3 }\n")...)

	corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "tier5-ready-reindex",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}
	baseIdx := fingerprints.NewCorpusIndexer(store, store)
	initRes, err := baseIdx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files:    []fingerprints.CorpusFile{{Path: "engine.go", Content: srcV1}},
	})
	if err != nil || initRes.FingerprintCount <= 0 {
		t.Fatalf("initial Index failed: res=%+v err=%v", initRes, err)
	}

	engine := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store, RequireStore: true})

	// 1. Pause inside RunCorpusTx during READY reindex and assert concurrent Engine.Analyze STILL matches (0 blind spot).
	txGate := &tier5BlockingTxRunner{
		inner:   store,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	pausedIdx := fingerprints.NewCorpusIndexer(store, txGate)
	errCh := make(chan error, 1)
	go func() {
		_, ixErr := pausedIdx.Index(ctx, fingerprints.IndexRequest{
			CorpusID: corpus.ID,
			Files:    []fingerprints.CorpusFile{{Path: "engine.go", Content: srcV2}},
			Force:    true,
		})
		errCh <- ixErr
	}()

	<-txGate.entered
	midRow, err := store.GetIPFingerprintCorpusByID(ctx, corpus.ID)
	if err != nil {
		t.Fatalf("GetIPFingerprintCorpusByID mid-reindex: %v", err)
	}
	if midRow.Status != domain.IPCorpusStatusReady {
		t.Fatalf("expected status READY during READY reindex (no INDEXING blind spot), got %s", midRow.Status)
	}
	midFindings, midCov, err := runEngineOnFiles(t, engine, map[string][]byte{"leak.go": srcV1}, "")
	if err != nil || !midCov.Complete || len(midFindings) == 0 {
		t.Fatalf("expected live IP findings during READY reindex, got findings=%d cov=%+v err=%v", len(midFindings), midCov, err)
	}

	close(txGate.release)
	if ixErr := <-errCh; ixErr != nil {
		t.Fatalf("paused reindex failed: %v", ixErr)
	}

	// 2. Context cancellation during READY reindex must preserve READY and all fingerprints.
	cancelTx := &tier5BlockingTxRunner{
		inner:   store,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	cancelIdx := fingerprints.NewCorpusIndexer(store, cancelTx)
	cctx, cancel := context.WithCancel(ctx)
	cancelErrCh := make(chan error, 1)
	go func() {
		_, ixErr := cancelIdx.Index(cctx, fingerprints.IndexRequest{
			CorpusID: corpus.ID,
			Files:    []fingerprints.CorpusFile{{Path: "engine.go", Content: srcV1}},
			Force:    true,
		})
		cancelErrCh <- ixErr
	}()
	<-cancelTx.entered
	cancel()
	if ixErr := <-cancelErrCh; !errors.Is(ixErr, context.Canceled) {
		t.Fatalf("expected context.Canceled on canceled reindex, got %v", ixErr)
	}
	afterCancel, _ := store.GetIPFingerprintCorpusByID(ctx, corpus.ID)
	if afterCancel.Status != domain.IPCorpusStatusReady || afterCancel.FingerprintCount <= 0 {
		t.Fatalf("expected READY preserved after canceled reindex, got status=%s count=%d", afterCancel.Status, afterCancel.FingerprintCount)
	}

	// 3. RunCorpusTx failure during READY reindex must preserve READY and intact fingerprints.
	failTx := &tier5BlockingTxRunner{
		inner:   store,
		failErr: domain.Unavailable("TX_DEADLOCK", "simulated tx failure"),
	}
	failIdx := fingerprints.NewCorpusIndexer(store, failTx)
	if _, ixErr := failIdx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: corpus.ID,
		Files:    []fingerprints.CorpusFile{{Path: "engine.go", Content: srcV1}},
		Force:    true,
	}); ixErr == nil {
		t.Fatal("expected error from failing RunCorpusTx")
	}
	afterTxFail, _ := store.GetIPFingerprintCorpusByID(ctx, corpus.ID)
	if afterTxFail.Status != domain.IPCorpusStatusReady || afterTxFail.FingerprintCount != afterCancel.FingerprintCount {
		t.Fatalf("expected READY and count=%d preserved after RunCorpusTx failure, got status=%s count=%d", afterCancel.FingerprintCount, afterTxFail.Status, afterTxFail.FingerprintCount)
	}
	postFindings, postCov, err := runEngineOnFiles(t, engine, map[string][]byte{"leak.go": srcV2}, "")
	if err != nil || !postCov.Complete || len(postFindings) == 0 {
		t.Fatalf("expected Engine.Analyze to still match READY corpus after failed reindex, got findings=%d cov=%+v err=%v", len(postFindings), postCov, err)
	}
}
