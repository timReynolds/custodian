package fingerprints

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	engineName    = string(inspection.ScannerIPFingerprint)
	engineVersion = "1.0.0"
)

// EngineConfig configures deterministic L1-L4 IP fingerprinting and concealment inspection.
type EngineConfig struct {
	Store               FingerprintLookupStore
	RequireStore        bool
	MaxFileInspectBytes int64
	WinnowK             int
	WinnowW             int
	ChunkSizeBytes      int
	MinWinnowMatches    int
}

// Engine implements inspection.IPFingerprinter across L1 exact chunking, L2 Winnowing,
// L3 proprietary headers & stripped-header detection, and L4 concealment inspection.
type Engine struct {
	cfg EngineConfig
}

var _ inspection.IPFingerprinter = (*Engine)(nil)

// NewEngine constructs an L1-L4 IP fingerprinting Engine with safe defaults.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.WinnowK <= 0 {
		cfg.WinnowK = defaultWinnowK
	}
	if cfg.WinnowW <= 0 {
		cfg.WinnowW = defaultWinnowW
	}
	if cfg.ChunkSizeBytes <= 0 {
		cfg.ChunkSizeBytes = defaultChunkSizeBytes
	}
	if cfg.MinWinnowMatches <= 0 {
		cfg.MinWinnowMatches = defaultMinWinnowMatches
	}
	return &Engine{cfg: cfg}
}

func (e *Engine) Name() string {
	return engineName
}

func (e *Engine) Version() string {
	return engineVersion
}

type preparedScanBuffer struct {
	buf             inspectedBuffer
	l1Chunks        []L1Chunk
	lang            string
	l2Winnows       []WinnowFingerprint
	header          HeaderExtraction
	candidateL3Hash []string
}

// Analyze inspects all workspace files in inv through L1-L4 without ever leaking raw source.
func (e *Engine) Analyze(ctx context.Context, req inspection.Request, inv *inspection.Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.ScanCoverage{Complete: false}, err
	}

	var bytesExamined int64
	if inv != nil {
		bytesExamined = inv.BytesExamined
	}

	if e.cfg.RequireStore && e.cfg.Store == nil {
		examined := 0
		if inv != nil {
			examined = inv.FilesExamined
		}
		return nil, domain.ScanCoverage{
			FilesExamined:  examined,
			FilesSkipped:   0,
			BytesExamined:  bytesExamined,
			SkippedReasons: []string{"ip_fingerprint_store_unconfigured"},
			Complete:       false,
		}, domain.Unavailable("IP_FINGERPRINT_STORE_UNCONFIGURED", "ip fingerprint lookup store is required")
	}

	if inv == nil {
		return nil, domain.ScanCoverage{
			FilesExamined:  0,
			FilesSkipped:   0,
			BytesExamined:  0,
			SkippedReasons: []string{},
			Complete:       true,
		}, nil
	}

	var (
		findings      []domain.Finding
		prepared      []preparedScanBuffer
		extraSkipped  int
		extraReasons  []string
		filesExamined int
	)

	l1HashSet := make(map[string]struct{})
	l2HashSet := make(map[string]struct{})
	l3HashSet := make(map[string]struct{})

	for _, entry := range inv.Files {
		if err := ctx.Err(); err != nil {
			return nil, domain.ScanCoverage{Complete: false}, err
		}
		if e.cfg.MaxFileInspectBytes > 0 && entry.Size > e.cfg.MaxFileInspectBytes {
			extraSkipped++
			extraReasons = append(extraReasons, fmt.Sprintf("oversized_file:%s", sanitizeReasonPath(entry.RelPath)))
			continue
		}

		data, tooLarge, readErr := readFileBounded(entry.AbsPath, e.cfg.MaxFileInspectBytes)
		if readErr != nil {
			extraSkipped++
			extraReasons = append(extraReasons, fmt.Sprintf("unreadable:%s", sanitizeReasonPath(entry.RelPath)))
			continue
		}
		if tooLarge {
			extraSkipped++
			extraReasons = append(extraReasons, fmt.Sprintf("oversized_file:%s", sanitizeReasonPath(entry.RelPath)))
			continue
		}

		filesExamined++
		l4Res := inspectFileL4(ctx, entry.RelPath, data)
		if err := ctx.Err(); err != nil {
			return nil, domain.ScanCoverage{Complete: false}, err
		}
		findings = append(findings, l4Res.Findings...)
		extraSkipped += l4Res.ExtraSkipped
		extraReasons = append(extraReasons, l4Res.SkippedReasons...)

		for _, buf := range l4Res.InspectBuffers {
			l1 := ExtractL1Chunks(buf.VirtualPath, buf.Data, e.cfg.ChunkSizeBytes)
			lang, l2 := ExtractL2Winnow(buf.VirtualPath, buf.Data, e.cfg.WinnowK, e.cfg.WinnowW)
			hdr := ExtractHeadersAndBodyForBuffer(buf.Data, buf.ExtractedMedia)
			candMarkers := ExtractCandidateMarkerHashes(buf.Data)

			for _, c := range l1 {
				l1HashSet[c.HashHex] = struct{}{}
			}
			for _, w := range l2 {
				l2HashSet[w.HashHex] = struct{}{}
			}
			for _, h := range candMarkers {
				l3HashSet[h] = struct{}{}
			}
			if hdr.HeaderlessBodyHash != "" {
				l3HashSet[hdr.HeaderlessBodyHash] = struct{}{}
			}

			prepared = append(prepared, preparedScanBuffer{
				buf:             buf,
				l1Chunks:        l1,
				lang:            lang,
				l2Winnows:       l2,
				header:          hdr,
				candidateL3Hash: candMarkers,
			})
		}
	}

	l1HitsByHash := make(map[string][]persistence.IPFingerprintLookupRow)
	l2HitsByHash := make(map[string][]persistence.IPFingerprintLookupRow)
	l3HitsByHash := make(map[string][]persistence.IPFingerprintLookupRow)

	if e.cfg.Store != nil {
		if len(l1HashSet) > 0 {
			rows, err := e.cfg.Store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL1ExactChunk, mapKeysSorted(l1HashSet))
			if err != nil {
				return nil, failClosedCoverage(filesExamined, extraSkipped, bytesExamined, extraReasons, "fingerprint_store_lookup_failed"), err
			}
			for _, r := range rows {
				l1HitsByHash[r.FingerprintHash] = append(l1HitsByHash[r.FingerprintHash], r)
			}
		}
		if len(l2HashSet) > 0 {
			rows, err := e.cfg.Store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL2WinnowKGram, mapKeysSorted(l2HashSet))
			if err != nil {
				return nil, failClosedCoverage(filesExamined, extraSkipped, bytesExamined, extraReasons, "fingerprint_store_lookup_failed"), err
			}
			for _, r := range rows {
				l2HitsByHash[r.FingerprintHash] = append(l2HitsByHash[r.FingerprintHash], r)
			}
		}
		if len(l3HashSet) > 0 {
			rows, err := e.cfg.Store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL3HeaderMarker, mapKeysSorted(l3HashSet))
			if err != nil {
				return nil, failClosedCoverage(filesExamined, extraSkipped, bytesExamined, extraReasons, "fingerprint_store_lookup_failed"), err
			}
			for _, r := range rows {
				l3HitsByHash[r.FingerprintHash] = append(l3HitsByHash[r.FingerprintHash], r)
			}
		}
	}

	// Track containers & stripped-header paths to avoid duplicate container/diff findings.
	encodedTriggered := make(map[string]struct{})
	archiveTriggered := make(map[string]struct{})
	headerStrippedPaths := make(map[string]struct{})

	for _, f := range findings {
		if f.Category == "IP_CONCEALMENT" && strings.Contains(f.Path, "#") {
			root, _, _ := strings.Cut(f.Path, "#")
			encodedTriggered[root] = struct{}{}
		}
		if f.Category == "IP_CONCEALMENT" && strings.Contains(f.Path, "!") {
			root, _, _ := strings.Cut(f.Path, "!")
			archiveTriggered[root] = struct{}{}
		}
	}
	for _, f := range findings {
		if f.Category == "SECRET" && strings.Contains(f.Path, "!") {
			root, _, _ := strings.Cut(f.Path, "!")
			if _, seen := archiveTriggered[root]; !seen {
				archiveTriggered[root] = struct{}{}
				findings = append(findings, makeConcealmentFinding(
					"ip.l4.nested-archive-payload",
					domain.SeverityHigh,
					root,
					"concealed secret payload inside archive",
					map[string]any{
						"layer":     "L4_CONCEALMENT",
						"technique": "nested_archive_payload",
					},
					"archive_secret:"+f.Path,
				))
			}
		}
	}

	for _, pb := range prepared {
		relPath := pb.buf.VirtualPath
		hadBufferHit := false

		// Track whether any matched corpus file for this buffer had a proprietary header.
		type matchedCorpusHeaderInfo struct {
			corpusID       uuid.UUID
			corpusName     string
			classification domain.Classification
			hasHeader      bool
		}
		corpusHeaderInfo := make(map[uuid.UUID]*matchedCorpusHeaderInfo)
		recordCorpusHeader := func(row persistence.IPFingerprintLookupRow, hasHdr bool) {
			info, ok := corpusHeaderInfo[row.CorpusID]
			if !ok {
				info = &matchedCorpusHeaderInfo{
					corpusID:       row.CorpusID,
					corpusName:     row.CorpusName,
					classification: row.Classification,
					hasHeader:      hasHdr,
				}
				corpusHeaderInfo[row.CorpusID] = info
			} else if hasHdr {
				info.hasHeader = true
			}
		}

		// --- L1 Exact Chunk Matches ---
		type l1CorpusAgg struct {
			corpusID       uuid.UUID
			corpusName     string
			classification domain.Classification
			matchCount     int
			minLine        int
			maxLine        int
			firstHash      string
		}
		l1Agg := make(map[uuid.UUID]*l1CorpusAgg)
		for _, chunk := range pb.l1Chunks {
			for _, hit := range l1HitsByHash[chunk.HashHex] {
				recordCorpusHeader(hit, rowCorpusHasHeader(hit))
				agg, ok := l1Agg[hit.CorpusID]
				if !ok {
					l1Agg[hit.CorpusID] = &l1CorpusAgg{
						corpusID:       hit.CorpusID,
						corpusName:     hit.CorpusName,
						classification: hit.Classification,
						matchCount:     1,
						minLine:        chunk.LineStart,
						maxLine:        chunk.LineEnd,
						firstHash:      chunk.HashHex,
					}
				} else {
					agg.matchCount++
					if chunk.LineStart > 0 && (agg.minLine == 0 || chunk.LineStart < agg.minLine) {
						agg.minLine = chunk.LineStart
					}
					if chunk.LineEnd > agg.maxLine {
						agg.maxLine = chunk.LineEnd
					}
				}
			}
		}
		for _, cid := range sortedUUIDKeys(l1Agg) {
			agg := l1Agg[cid]
			hadBufferHit = true
			sev := classificationSeverity(agg.classification)
			fp := inspection.ComputeFingerprint(engineName, "ip.l1.exact-chunk", relPath, agg.minLine, agg.maxLine, fmt.Sprintf("%s:%s", cid, agg.firstHash))
			evID := inspection.ComputeEvidenceID(engineName, "IP_EXACT", "ip.l1.exact-chunk", relPath, agg.minLine, agg.maxLine, fp)
			findings = append(findings, domain.Finding{
				Scanner:     engineName,
				EvidenceID:  evID,
				Category:    "IP_EXACT",
				Severity:    sev,
				RuleID:      "ip.l1.exact-chunk",
				Path:        relPath,
				StartLine:   agg.minLine,
				EndLine:     agg.maxLine,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     fmt.Sprintf("Exact chunk fingerprint match against %s corpus (%d chunk(s))", agg.classification, agg.matchCount),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":                 string(domain.FingerprintLayerL1ExactChunk),
					"classification":        string(agg.classification),
					"corpus_classification": string(agg.classification),
					"corpus_id":             agg.corpusID.String(),
					"corpus_name":           agg.corpusName,
					"fingerprint_hash":      agg.firstHash,
					"match_count":           agg.matchCount,
					"corpus_has_header":     corpusHeaderInfo[cid].hasHeader,
				},
			})
		}

		// --- L2 Winnowing k-gram Matches (>= MinWinnowMatches distinct hashes per corpus file) ---
		type l2FileGroupKey struct {
			corpusID     uuid.UUID
			filePathHash string
		}
		type l2FileGroup struct {
			corpusID       uuid.UUID
			corpusName     string
			classification domain.Classification
			distinctHashes map[string]struct{}
			minLine        int
			maxLine        int
			corpusHasHdr   bool
		}
		l2ByCorpusFile := make(map[l2FileGroupKey]*l2FileGroup)
		for _, w := range pb.l2Winnows {
			for _, hit := range l2HitsByHash[w.HashHex] {
				fph := ""
				if hit.FilePathHash != nil {
					fph = *hit.FilePathHash
				}
				gk := l2FileGroupKey{corpusID: hit.CorpusID, filePathHash: fph}
				grp, ok := l2ByCorpusFile[gk]
				if !ok {
					grp = &l2FileGroup{
						corpusID:       hit.CorpusID,
						corpusName:     hit.CorpusName,
						classification: hit.Classification,
						distinctHashes: make(map[string]struct{}),
						minLine:        w.LineStart,
						maxLine:        w.LineEnd,
					}
					l2ByCorpusFile[gk] = grp
				}
				grp.distinctHashes[w.HashHex] = struct{}{}
				if w.LineStart > 0 && (grp.minLine == 0 || w.LineStart < grp.minLine) {
					grp.minLine = w.LineStart
				}
				if w.LineEnd > grp.maxLine {
					grp.maxLine = w.LineEnd
				}
				if rowCorpusHasHeader(hit) {
					grp.corpusHasHdr = true
				}
			}
		}

		// Aggregate winning corpus matches (where distinctHashes >= MinWinnowMatches) per corpusID.
		l2BestByCorpus := make(map[uuid.UUID]*l2FileGroup)
		for _, grp := range l2ByCorpusFile {
			if len(grp.distinctHashes) < e.cfg.MinWinnowMatches {
				continue
			}
			recordCorpusHeader(persistence.IPFingerprintLookupRow{
				IPFingerprintRow: persistence.IPFingerprintRow{CorpusID: grp.corpusID},
				CorpusName:       grp.corpusName,
				Classification:   grp.classification,
			}, grp.corpusHasHdr)
			cur, exists := l2BestByCorpus[grp.corpusID]
			if !exists || len(grp.distinctHashes) > len(cur.distinctHashes) {
				l2BestByCorpus[grp.corpusID] = grp
			} else if grp.corpusHasHdr {
				cur.corpusHasHdr = true
			}
		}
		for _, cid := range sortedUUIDKeys(l2BestByCorpus) {
			grp := l2BestByCorpus[cid]
			hadBufferHit = true
			matchCount := len(grp.distinctHashes)
			sev := classificationSeverity(grp.classification)
			conf := 0.75 + 0.02*float64(matchCount)
			if conf > 0.99 {
				conf = 0.99
			}
			fp := inspection.ComputeFingerprint(engineName, "ip.l2.winnow-kgram", relPath, grp.minLine, grp.maxLine, fmt.Sprintf("%s:%d:%s", cid, matchCount, pb.lang))
			evID := inspection.ComputeEvidenceID(engineName, "IP_WINNOW", "ip.l2.winnow-kgram", relPath, grp.minLine, grp.maxLine, fp)
			findings = append(findings, domain.Finding{
				Scanner:     engineName,
				EvidenceID:  evID,
				Category:    "IP_WINNOW",
				Severity:    sev,
				RuleID:      "ip.l2.winnow-kgram",
				Path:        relPath,
				StartLine:   grp.minLine,
				EndLine:     grp.maxLine,
				Fingerprint: fp,
				Confidence:  conf,
				Message:     fmt.Sprintf("Lexical Winnowing similarity match against %s corpus (%d matching k-grams)", grp.classification, matchCount),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":                 string(domain.FingerprintLayerL2WinnowKGram),
					"classification":        string(grp.classification),
					"corpus_classification": string(grp.classification),
					"corpus_id":             grp.corpusID.String(),
					"corpus_name":           grp.corpusName,
					"language":              pb.lang,
					"match_count":           matchCount,
					"winnow_k":              e.cfg.WinnowK,
					"winnow_w":              e.cfg.WinnowW,
					"corpus_has_header":     grp.corpusHasHdr,
				},
			})
		}

		// --- L3a Proprietary Header Markers (Corpus-backed + Standalone Heuristic) ---
		type l3CorpusHit struct {
			corpusID       uuid.UUID
			corpusName     string
			classification domain.Classification
			markerKind     string
			matchCount     int
		}
		l3MarkerAgg := make(map[uuid.UUID]*l3CorpusHit)
		for _, mh := range pb.candidateL3Hash {
			for _, hit := range l3HitsByHash[mh] {
				if rowMarkerKind(hit) == "headerless_body" {
					continue
				}
				agg, ok := l3MarkerAgg[hit.CorpusID]
				if !ok {
					l3MarkerAgg[hit.CorpusID] = &l3CorpusHit{
						corpusID:       hit.CorpusID,
						corpusName:     hit.CorpusName,
						classification: hit.Classification,
						markerKind:     rowMarkerKind(hit),
						matchCount:     1,
					}
				} else {
					agg.matchCount++
				}
			}
		}

		hasCorpusL3HeaderHit := len(l3MarkerAgg) > 0
		for _, cid := range sortedUUIDKeys(l3MarkerAgg) {
			agg := l3MarkerAgg[cid]
			hadBufferHit = true
			sev := classificationSeverity(agg.classification)
			fp := inspection.ComputeFingerprint(engineName, "ip.l3.header-marker", relPath, 1, 1, fmt.Sprintf("corpus:%s:%s", cid, agg.markerKind))
			evID := inspection.ComputeEvidenceID(engineName, "IP_HEADER_MARKER", "ip.l3.header-marker", relPath, 1, 1, fp)
			findings = append(findings, domain.Finding{
				Scanner:     engineName,
				EvidenceID:  evID,
				Category:    "IP_HEADER_MARKER",
				Severity:    sev,
				RuleID:      "ip.l3.header-marker",
				Path:        relPath,
				StartLine:   1,
				EndLine:     leadingHeaderLineWindow,
				Fingerprint: fp,
				Confidence:  0.98,
				Message:     fmt.Sprintf("Proprietary header marker matches %s corpus (%s)", agg.classification, agg.markerKind),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":                 string(domain.FingerprintLayerL3HeaderMarker),
					"classification":        string(agg.classification),
					"corpus_classification": string(agg.classification),
					"corpus_id":             agg.corpusID.String(),
					"corpus_name":           agg.corpusName,
					"marker_kind":           agg.markerKind,
					"match_count":           agg.matchCount,
				},
			})
		}

		if !hasCorpusL3HeaderHit && pb.header.HasHeader {
			hadBufferHit = true
			cls := domain.ClassificationConfidential
			minLine := pb.header.Markers[0].LineStart
			maxLine := pb.header.Markers[0].LineEnd
			kind := pb.header.Markers[0].MarkerKind
			for _, m := range pb.header.Markers {
				if m.Classification == domain.ClassificationRestricted {
					cls = domain.ClassificationRestricted
				}
				if m.LineStart < minLine {
					minLine = m.LineStart
				}
				if m.LineEnd > maxLine {
					maxLine = m.LineEnd
				}
			}
			sev := classificationSeverity(cls)
			fp := inspection.ComputeFingerprint(engineName, "ip.l3.header-marker", relPath, minLine, maxLine, fmt.Sprintf("heuristic:%s:%s", cls, kind))
			evID := inspection.ComputeEvidenceID(engineName, "IP_HEADER_MARKER", "ip.l3.header-marker", relPath, minLine, maxLine, fp)
			findings = append(findings, domain.Finding{
				Scanner:     engineName,
				EvidenceID:  evID,
				Category:    "IP_HEADER_MARKER",
				Severity:    sev,
				RuleID:      "ip.l3.header-marker",
				Path:        relPath,
				StartLine:   minLine,
				EndLine:     maxLine,
				Fingerprint: fp,
				Confidence:  0.92,
				Message:     fmt.Sprintf("Proprietary copyright or classification header detected (%s)", cls),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":                 string(domain.FingerprintLayerL3HeaderMarker),
					"classification":        string(cls),
					"corpus_classification": string(cls),
					"marker_kind":           kind,
					"heuristic_only":        true,
					"match_count":           len(pb.header.Markers),
				},
			})
		}

		// --- L3b Headerless Body Match & Stripped-Header Detection (without diff) ---
		if pb.header.HeaderlessBodyHash != "" {
			for _, hit := range l3HitsByHash[pb.header.HeaderlessBodyHash] {
				if rowMarkerKind(hit) == "headerless_body" {
					recordCorpusHeader(hit, true)
				}
			}
		}

		if !pb.header.HasHeader && !hasCorpusL3HeaderHit {
			for _, cid := range sortedUUIDKeys(corpusHeaderInfo) {
				info := corpusHeaderInfo[cid]
				if !info.hasHeader {
					continue
				}
				hadBufferHit = true
				headerStrippedPaths[relPath] = struct{}{}
				fp := inspection.ComputeFingerprint(engineName, "ip.l3.header-stripped", relPath, 1, 1, fmt.Sprintf("strip:%s", cid))
				evID := inspection.ComputeEvidenceID(engineName, "IP_HEADER_STRIP", "ip.l3.header-stripped", relPath, 1, 1, fp)
				findings = append(findings, domain.Finding{
					Scanner:     engineName,
					EvidenceID:  evID,
					Category:    "IP_HEADER_STRIP",
					Severity:    domain.SeverityCritical,
					RuleID:      "ip.l3.header-stripped",
					Path:        relPath,
					StartLine:   1,
					EndLine:     1,
					Fingerprint: fp,
					Confidence:  0.96,
					Message:     fmt.Sprintf("Proprietary copyright/classification header stripped from %s corpus file", info.classification),
					Redacted:    true,
					Metadata: map[string]any{
						"layer":                 string(domain.FingerprintLayerL3HeaderMarker),
						"header_stripped":       true,
						"classification":        string(info.classification),
						"corpus_classification": string(info.classification),
						"corpus_id":             info.corpusID.String(),
						"corpus_name":           info.corpusName,
						"detection_mode":        "corpus_body_without_header",
					},
				})
			}
		}

		// Back-attribute container concealment if IP hit occurred inside encoded/archived payload.
		if hadBufferHit {
			if pb.buf.InEncoded && strings.Contains(relPath, "#") {
				root, rest, _ := strings.Cut(relPath, "#")
				if _, seen := encodedTriggered[root]; !seen {
					encodedTriggered[root] = struct{}{}
					encKind := "encoded"
					if strings.HasPrefix(rest, "b64") {
						encKind = "b64"
					} else if strings.HasPrefix(rest, "hex") {
						encKind = "hex"
					}
					findings = append(findings, makeConcealmentFinding(
						"ip.l4.encoded-payload",
						domain.SeverityHigh,
						root,
						fmt.Sprintf("concealed %s-encoded IP payload detected", encKind),
						map[string]any{
							"layer":     "L4_CONCEALMENT",
							"technique": "encoded_payload",
							"encoding":  encKind,
						},
						"encoded_ip:"+relPath,
					))
				}
			}
			if pb.buf.InArchive && strings.Contains(relPath, "!") {
				root, _, _ := strings.Cut(relPath, "!")
				if _, seen := archiveTriggered[root]; !seen {
					archiveTriggered[root] = struct{}{}
					findings = append(findings, makeConcealmentFinding(
						"ip.l4.nested-archive-payload",
						domain.SeverityHigh,
						root,
						"concealed IP or sensitive payload inside archive",
						map[string]any{
							"layer":     "L4_CONCEALMENT",
							"technique": "nested_archive_payload",
						},
						"archive_ip:"+relPath,
					))
				}
			}
		}
	}

	// --- L3b Mode 2: UnifiedDiff stripped-header detection ---
	if req.UnifiedDiff != "" {
		for _, strip := range DetectStrippedHeadersInUnifiedDiff(req.UnifiedDiff) {
			if _, seen := headerStrippedPaths[strip.RelPath]; seen {
				continue
			}
			headerStrippedPaths[strip.RelPath] = struct{}{}
			fp := inspection.ComputeFingerprint(engineName, "ip.l3.header-stripped", strip.RelPath, strip.LineStart, strip.LineEnd, "diff_strip:"+strip.RelPath)
			evID := inspection.ComputeEvidenceID(engineName, "IP_HEADER_STRIP", "ip.l3.header-stripped", strip.RelPath, strip.LineStart, strip.LineEnd, fp)
			findings = append(findings, domain.Finding{
				Scanner:     engineName,
				EvidenceID:  evID,
				Category:    "IP_HEADER_STRIP",
				Severity:    domain.SeverityCritical,
				RuleID:      "ip.l3.header-stripped",
				Path:        strip.RelPath,
				StartLine:   strip.LineStart,
				EndLine:     strip.LineEnd,
				Fingerprint: fp,
				Confidence:  0.95,
				Message:     fmt.Sprintf("Unified diff removed proprietary copyright/classification header (%s)", strip.Classification),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":                 string(domain.FingerprintLayerL3HeaderMarker),
					"header_stripped":       true,
					"classification":        string(strip.Classification),
					"corpus_classification": string(strip.Classification),
					"detection_mode":        "diff_header_removal",
				},
			})
		}
	}

	dedupedReasons := dedupeStrings(extraReasons)
	complete := extraSkipped == 0 && len(dedupedReasons) == 0 && inv.FilesSkipped == 0 && len(inv.SkippedReasons) == 0
	return findings, domain.ScanCoverage{
		FilesExamined:  filesExamined,
		FilesSkipped:   extraSkipped,
		BytesExamined:  bytesExamined,
		SkippedReasons: dedupedReasons,
		Complete:       complete,
	}, nil
}

func readFileBounded(absPath string, maxBytes int64) ([]byte, bool, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	if maxBytes <= 0 {
		data, err := io.ReadAll(f)
		return data, false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, true, nil
	}
	return data, false, nil
}

func failClosedCoverage(examined, skipped int, bytesExamined int64, reasons []string, extraReason string) domain.ScanCoverage {
	all := append(append([]string(nil), reasons...), extraReason)
	return domain.ScanCoverage{
		FilesExamined:  examined,
		FilesSkipped:   skipped,
		BytesExamined:  bytesExamined,
		SkippedReasons: dedupeStrings(all),
		Complete:       false,
	}
}

func classificationSeverity(cls domain.Classification) domain.Severity {
	if cls == domain.ClassificationRestricted {
		return domain.SeverityCritical
	}
	return domain.SeverityHigh
}

func rowCorpusHasHeader(row persistence.IPFingerprintLookupRow) bool {
	if len(row.Metadata) == 0 {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(row.Metadata, &m); err != nil {
		return false
	}
	v, ok := m["corpus_has_header"].(bool)
	return ok && v
}

func rowMarkerKind(row persistence.IPFingerprintLookupRow) string {
	if len(row.Metadata) == 0 {
		return "copyright"
	}
	var m map[string]any
	if err := json.Unmarshal(row.Metadata, &m); err != nil {
		return "copyright"
	}
	if v, ok := m["marker_kind"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return "copyright"
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedUUIDKeys[V any](m map[uuid.UUID]V) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
