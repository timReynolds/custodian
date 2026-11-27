package fingerprints

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

const leadingHeaderLineWindow = 40

// HeaderMarker describes a normalized copyright, confidentiality, or classification banner.
type HeaderMarker struct {
	LineStart      int
	LineEnd        int
	MarkerKind     string // "copyright" | "classification" | "trade_secret"
	HashHex        string // SHA-256 of "marker:<normalized>"
	Classification domain.Classification
}

// HeaderExtraction summarizes leading proprietary markers and headerless body for a file.
type HeaderExtraction struct {
	HasHeader          bool
	Markers            []HeaderMarker
	HeaderlessBody     string
	HeaderlessBodyHash string // SHA-256 of "body:<HeaderlessBody>", empty if < 64 non-ws bytes
}

var (
	ossLicenseRe = regexp.MustCompile(`(?i)\b(?:spdx-license-identifier|mit\s+license|apache\s+license|bsd\s+\d-clause|permission\s+is\s+hereby\s+granted|redistribution\s+and\s+use\s+in\s+source\s+and\s+binary|gnu\s+(?:general|lesser|affero)\s+public\s+license|mozilla\s+public\s+license|isc\s+license)\b`)

	classificationBannerRe  = regexp.MustCompile(`(?i)\bclassification\s*:\s*(restricted|confidential)\b`)
	explicitProprietaryRe   = regexp.MustCompile(`(?i)\b(?:trade\s+secret|do\s+not\s+(?:copy|distribute|transmit|disclose)|unauthorized\s+(?:copying|reverse\s+engineering|exfiltration|distribution)|proprietary\s+(?:and\s+|&\s+)?confidential|confidential\s+(?:and\s+|&\s+)?proprietary|proprietary\s+(?:source|code|ip|algorithm|software|material|information|systems?\b)|restricted\s+(?:use|distribution|access|source|ip|data|circulation|proprietary|material|information)|strictly\s+(?:prohibited|confidential|restricted))\b|\(\s*restricted\s*\)`)
	explicitConfidentialRe  = regexp.MustCompile(`(?i)\b(?:internal\s+use\s+only|strictly\s+confidential|confidential\s+(?:and\s+proprietary|information|material|source|code|internal))\b`)
	nonOSSProprietaryTermRe = regexp.MustCompile(`(?i)\b(?:proprietary|trade\s+secret|do\s+not\s+(?:copy|distribute|transmit|disclose)|unauthorized\s+(?:copying|reverse\s+engineering|exfiltration|distribution))\b`)
	confidentialTermRe      = regexp.MustCompile(`(?i)\b(?:confidential|internal\s+use\s+only)\b`)
	copyrightNoticeRe       = regexp.MustCompile(`(?i)\bcopyright\s*(?:\(c\)|©)?\s*(?:19|20)\d{2}\b`)
	allRightsReservedRe     = regexp.MustCompile(`(?i)\ball\s+rights\s+reserved\b`)
)

// ExtractHeadersAndBody inspects the leading 40 lines for proprietary copyright/confidentiality
// banners while excluding bare OSS copyright headers. It also derives a normalized headerless body.
func ExtractHeadersAndBody(data []byte) HeaderExtraction {
	return extractHeadersAndBody(data, true)
}

// ExtractHeadersAndBodyForBuffer behaves like ExtractHeadersAndBody, but suppresses the bare
// heuristic-only copyright+all-rights-reserved trigger when extractedMedia is true.
func ExtractHeadersAndBodyForBuffer(data []byte, extractedMedia bool) HeaderExtraction {
	return extractHeadersAndBody(data, !extractedMedia)
}

// ExtractHeadersAndBodyForPath behaves like ExtractHeadersAndBody, but suppresses the bare
// heuristic-only copyright+all-rights-reserved trigger on extracted media/ICC printable buffers.
// Deprecated: prefer ExtractHeadersAndBodyForBuffer with explicit ExtractedMedia metadata.
func ExtractHeadersAndBodyForPath(virtualPath string, data []byte) HeaderExtraction {
	return extractHeadersAndBody(data, !isExtractedMediaPrintablePath(virtualPath))
}

func isExtractedMediaPrintablePath(virtualPath string) bool {
	if virtualPath == "" {
		return false
	}
	idx := strings.IndexByte(virtualPath, '#')
	if idx < 0 {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(virtualPath[idx+1:]), "#") {
		if seg == "printable" || seg == "icc" || seg == "8bim" || seg == "exif" || seg == "xmp" ||
			seg == "wasm_sections" || seg == "pdf_nonstream" ||
			strings.HasPrefix(seg, "webp_") || strings.HasPrefix(seg, "png_") ||
			strings.HasPrefix(seg, "jpeg_") || strings.HasPrefix(seg, "pdf_") ||
			strings.HasPrefix(seg, "type1_") ||
			((strings.HasPrefix(seg, "pdfstream[") || strings.HasPrefix(seg, "pdfdct[")) && strings.HasSuffix(seg, "]")) {
			return true
		}
	}
	return false
}

func extractHeadersAndBody(data []byte, allowBareCopyrightHeuristic bool) HeaderExtraction {
	if looksBinary(data) {
		return HeaderExtraction{}
	}
	norm := normalizeText(data)
	lines := strings.Split(norm, "\n")
	if len(lines) == 0 {
		return HeaderExtraction{}
	}

	limit := len(lines)
	if limit > leadingHeaderLineWindow {
		limit = leadingHeaderLineWindow
	}

	// Evaluate OSS exemption across the entire leading block so multi-line OSS notices aren't flagged.
	leadingBlock := strings.Join(lines[:limit], "\n")
	mayMatchHeader := len(leadingBlock) <= 4096 || blockMayContainHeaderKeyword(leadingBlock)
	var hasOSSLicense, hasStrongProprietary bool
	if mayMatchHeader {
		hasOSSLicense = ossLicenseRe.MatchString(leadingBlock)
		hasStrongProprietary = hasStrongProprietaryInBlock(leadingBlock, hasOSSLicense)
	}

	var markers []HeaderMarker
	lastHeaderLineIdx := -1
	inBlockComment := false
	sawCommentLine := false
	sawNonEmptyLine := false
	sawBlankAfterNonEmpty := false

	for idx := 0; idx < limit; idx++ {
		trimmed := strings.TrimSpace(lines[idx])
		if trimmed == "" {
			if sawNonEmptyLine {
				sawBlankAfterNonEmpty = true
			}
			continue
		}
		if idx == 0 && strings.HasPrefix(trimmed, "#!") {
			lastHeaderLineIdx = idx
			sawNonEmptyLine = true
			continue
		}

		// Handle single-line block comment with trailing code on the same line (e.g. `/* note */ import ...`).
		hasTrailingAfterBlock := false
		lineForHeader := trimmed
		if !inBlockComment && strings.HasPrefix(trimmed, "/*") {
			if endRel := strings.Index(trimmed[2:], "*/"); endRel >= 0 {
				endIdx := 2 + endRel + 2
				if strings.TrimSpace(trimmed[endIdx:]) != "" {
					hasTrailingAfterBlock = true
					lineForHeader = strings.TrimSpace(trimmed[:endIdx])
				}
			}
		}

		isCommentLine, nextInBlock := classifyLeadingLine(lineForHeader, inBlockComment)
		inBlockComment = nextInBlock

		if !isCommentLine {
			// Non-comment code lines (and non-comment lines after a leading comment block, blank separator, or line 3)
			// must terminate leading header scanning before classifyHeaderLine runs.
			if looksLikeCodeLine(trimmed) || sawCommentLine || sawBlankAfterNonEmpty || idx >= 3 {
				break
			}
		} else {
			sawCommentLine = true
		}
		sawNonEmptyLine = true

		cleaned := stripCommentDelimiters(lineForHeader)
		if cleaned == "" {
			if isCommentLine {
				lastHeaderLineIdx = idx
			}
			if hasTrailingAfterBlock {
				break
			}
			continue
		}

		var kind string
		var cls domain.Classification
		var matched bool
		if mayMatchHeader {
			kind, cls, matched = classifyHeaderLine(cleaned, hasOSSLicense, hasStrongProprietary, allowBareCopyrightHeuristic)
		}
		if matched {
			normMarker := normalizeHeaderLine(cleaned)
			markers = append(markers, HeaderMarker{
				LineStart:      idx + 1,
				LineEnd:        idx + 1,
				MarkerKind:     kind,
				HashHex:        sha256HexString("marker:" + normMarker),
				Classification: cls,
			})
			lastHeaderLineIdx = idx
			if hasTrailingAfterBlock {
				break
			}
			continue
		}
		if hasTrailingAfterBlock {
			break
		}
		if isCommentLine {
			lastHeaderLineIdx = idx
			continue
		}
	}

	res := HeaderExtraction{
		HasHeader: len(markers) > 0,
		Markers:   markers,
	}
	if len(markers) > 0 && lastHeaderLineIdx+1 < len(lines) {
		body := strings.TrimLeft(strings.Join(lines[lastHeaderLineIdx+1:], "\n"), "\n")
		if countNonWhitespaceBytes(body) >= minNonWhitespaceBytesL1 {
			res.HeaderlessBody = body
			res.HeaderlessBodyHash = sha256HexString("body:" + body)
		}
	} else if len(markers) == 0 && countNonWhitespaceBytes(norm) >= minNonWhitespaceBytesL1 {
		// For pushed files without headers, compute candidate headerless body hash for corpus lookup.
		body := strings.TrimLeft(norm, "\n")
		res.HeaderlessBody = body
		res.HeaderlessBodyHash = sha256HexString("body:" + body)
	}
	return res
}

// ExtractCandidateMarkerHashes returns normalized hashes for leading lines (up to 40)
// so corpus-indexed L3 markers can still match even if an OSS-looking wording was customized.
func ExtractCandidateMarkerHashes(data []byte) []string {
	if looksBinary(data) {
		return nil
	}
	norm := normalizeText(data)
	lines := strings.Split(norm, "\n")
	limit := len(lines)
	if limit > leadingHeaderLineWindow {
		limit = leadingHeaderLineWindow
	}
	seen := make(map[string]struct{}, limit)
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		cleaned := normalizeHeaderLine(stripCommentDelimiters(lines[i]))
		if len(cleaned) < 12 {
			continue
		}
		h := sha256HexString("marker:" + cleaned)
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

func classifyLeadingLine(trimmed string, inBlock bool) (isComment bool, nextInBlock bool) {
	if inBlock {
		if strings.Contains(trimmed, "*/") {
			return true, false
		}
		return true, true
	}
	if looksLikeCodeLine(trimmed) {
		return false, false
	}
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") {
		return true, false
	}
	if strings.HasPrefix(trimmed, "/*") {
		if strings.Contains(trimmed[2:], "*/") {
			return true, false
		}
		return true, true
	}
	if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
		return true, false
	}
	return false, false
}

func looksLikeCodeLine(trimmed string) bool {
	for _, prefix := range []string{
		"package ", "import ", "import(", "import{", "export ", "export{",
		"func ", "type ", "var ", "const ", "let ", "function ", "async ",
		"def ", "class ", "from ", "from(",
		"#include", "#define ", "#ifdef ", "#ifndef ", "#pragma ", "#[", "#![",
		"using ", "use ", "mod ", "pub ", "fn ", "struct ", "enum ", "interface ", "trait ", "impl ",
		"namespace ", "module ", "public ", "private ", "protected ", "internal ",
		"require ", "require_relative ", "return ",
		"<?php", "<?xml", "<!DOCTYPE", "<!doctype", "<html", "{", "[",
	} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func stripCommentDelimiters(line string) string {
	s := strings.TrimSpace(line)
	for {
		prev := s
		s = strings.TrimSpace(strings.TrimPrefix(s, "//"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "/*"))
		s = strings.TrimSpace(strings.TrimSuffix(s, "*/"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "*"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "#"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "--"))
		s = strings.TrimSpace(strings.Trim(s, `"`))
		s = strings.TrimSpace(strings.Trim(s, `'`))
		if s == prev {
			break
		}
	}
	return s
}

func blockMayContainHeaderKeyword(block string) bool {
	lower := strings.ToLower(block)
	for _, kw := range []string{
		"licens", "bsd", "permiss", "redistrib",
		"classif", "secret", "copy", "distrib",
		"transmi", "disclos", "unauth", "propriet",
		"confid", "strict", "intern", "reserv",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func normalizeHeaderLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hasStrongProprietaryInBlock(block string, hasOSSLicense bool) bool {
	if classificationBannerRe.MatchString(block) ||
		explicitProprietaryRe.MatchString(block) ||
		explicitConfidentialRe.MatchString(block) {
		return true
	}
	if !hasOSSLicense {
		return nonOSSProprietaryTermRe.MatchString(block) || confidentialTermRe.MatchString(block)
	}
	return false
}

func classifyHeaderLine(cleaned string, hasOSSLicense, hasStrongProprietary, allowBareCopyrightHeuristic bool) (kind string, cls domain.Classification, matched bool) {
	// Safe OSS exclusion: bare OSS copyright / license headers without explicit proprietary/confidential banners never heuristic-trigger.
	if hasOSSLicense && !hasStrongProprietary {
		return "", "", false
	}

	if m := classificationBannerRe.FindStringSubmatch(cleaned); len(m) == 2 {
		if strings.EqualFold(m[1], "RESTRICTED") {
			return "classification", domain.ClassificationRestricted, true
		}
		return "classification", domain.ClassificationConfidential, true
	}

	var hasProp, hasConf bool
	if hasOSSLicense {
		hasProp = explicitProprietaryRe.MatchString(cleaned)
		hasConf = explicitConfidentialRe.MatchString(cleaned)
	} else {
		hasProp = explicitProprietaryRe.MatchString(cleaned) || nonOSSProprietaryTermRe.MatchString(cleaned)
		hasConf = explicitConfidentialRe.MatchString(cleaned) || confidentialTermRe.MatchString(cleaned)
	}
	hasCopy := copyrightNoticeRe.MatchString(cleaned)
	hasAllRights := allRightsReservedRe.MatchString(cleaned)

	if hasProp {
		kind = "trade_secret"
		if hasCopy {
			kind = "copyright"
		}
		return kind, domain.ClassificationRestricted, true
	}
	if hasConf {
		kind = "classification"
		if hasCopy {
			kind = "copyright"
		}
		return kind, domain.ClassificationConfidential, true
	}
	if hasCopy && hasAllRights && !hasOSSLicense {
		// Bare copyright + All Rights Reserved without explicit RESTRICTED/PROPRIETARY -> CONFIDENTIAL unless block has proprietary terms.
		if hasStrongProprietary {
			return "copyright", domain.ClassificationRestricted, true
		}
		if allowBareCopyrightHeuristic {
			return "copyright", domain.ClassificationConfidential, true
		}
	}
	return "", "", false
}

// DiffHeaderStrip describes a file whose leading proprietary header was removed in a unified diff.
type DiffHeaderStrip struct {
	RelPath        string
	Classification domain.Classification
	LineStart      int
	LineEnd        int
}

// DetectStrippedHeadersInUnifiedDiff inspects unified diff hunks for removal of leading proprietary headers.
func DetectStrippedHeadersInUnifiedDiff(unifiedDiff string) []DiffHeaderStrip {
	if strings.TrimSpace(unifiedDiff) == "" {
		return nil
	}
	lines := strings.Split(normalizeText([]byte(unifiedDiff)), "\n")

	var out []DiffHeaderStrip
	curPath := ""
	inLeadingHunk := false
	removedCleaned := make([]string, 0)
	addedCleaned := make([]string, 0)

	extractMarkers := func(cleanedLines []string) []HeaderMarker {
		if len(cleanedLines) == 0 {
			return nil
		}
		block := strings.Join(cleanedLines, "\n")
		hasOSS := ossLicenseRe.MatchString(block)
		hasStrong := hasStrongProprietaryInBlock(block, hasOSS)
		var markers []HeaderMarker
		for _, cleaned := range cleanedLines {
			if kind, cls, ok := classifyHeaderLine(cleaned, hasOSS, hasStrong, true); ok {
				markers = append(markers, HeaderMarker{
					LineStart:      1,
					LineEnd:        1,
					MarkerKind:     kind,
					Classification: cls,
				})
			}
		}
		return markers
	}

	flushFile := func() {
		if curPath != "" {
			removedMarkers := extractMarkers(removedCleaned)
			addedMarkers := extractMarkers(addedCleaned)
			if len(removedMarkers) > 0 && len(addedMarkers) == 0 {
				cls := domain.ClassificationConfidential
				minLine, maxLine := removedMarkers[0].LineStart, removedMarkers[0].LineEnd
				for _, m := range removedMarkers {
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
				out = append(out, DiffHeaderStrip{
					RelPath:        curPath,
					Classification: cls,
					LineStart:      max(minLine, 1),
					LineEnd:        max(maxLine, 1),
				})
			}
		}
		removedCleaned = removedCleaned[:0]
		addedCleaned = addedCleaned[:0]
		inLeadingHunk = false
	}

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flushFile()
			curPath = ""
		case strings.HasPrefix(line, "+++ "):
			p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			p = strings.TrimPrefix(p, "b/")
			if p == "/dev/null" {
				curPath = ""
			} else if p != "" {
				curPath = p
			}
		case strings.HasPrefix(line, "@@ "):
			oldStart := parseUnifiedHunkOldStart(line)
			inLeadingHunk = oldStart > 0 && oldStart <= leadingHeaderLineWindow
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "--- "):
			if inLeadingHunk {
				body := strings.TrimSpace(line[1:])
				if body != "" {
					isComment, _ := classifyLeadingLine(body, false)
					if isComment || !looksLikeCodeLine(body) {
						if cleaned := stripCommentDelimiters(body); cleaned != "" {
							removedCleaned = append(removedCleaned, cleaned)
						}
					}
				}
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++ "):
			if inLeadingHunk {
				body := strings.TrimSpace(line[1:])
				if body != "" {
					isComment, _ := classifyLeadingLine(body, false)
					if isComment || !looksLikeCodeLine(body) {
						if cleaned := stripCommentDelimiters(body); cleaned != "" {
							addedCleaned = append(addedCleaned, cleaned)
						}
					}
				}
			}
		}
	}
	flushFile()
	return out
}

func parseUnifiedHunkOldStart(hunkHeader string) int {
	// Format: @@ -<oldStart>[,<oldCount>] +<newStart>[,<newCount>] @@
	rest := strings.TrimPrefix(hunkHeader, "@@ ")
	minusIdx := strings.IndexByte(rest, '-')
	if minusIdx < 0 {
		return 0
	}
	rest = rest[minusIdx+1:]
	endIdx := strings.IndexAny(rest, ", ")
	if endIdx < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:endIdx])
	if err != nil {
		return 0
	}
	return n
}
