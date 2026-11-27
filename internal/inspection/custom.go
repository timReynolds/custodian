package inspection

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const customScannerVersion = "1.0.0"

var privateKeyBlockRe = regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----`)

var restrictedPathSegments = map[string]struct{}{
	"secrets":      {},
	"private_keys": {},
}

var restrictedExactFilenames = map[string]struct{}{
	".env":             {},
	".npmrc":           {},
	".pypirc":          {},
	".netrc":           {},
	".htpasswd":        {},
	"credentials.json": {},
}

var restrictedEnvAllowlist = map[string]struct{}{
	".env.example":  {},
	".env.sample":   {},
	".env.template": {},
}

var restrictedSecretExtensions = map[string]struct{}{
	".pem":      {},
	".key":      {},
	".p12":      {},
	".pfx":      {},
	".jks":      {},
	".keystore": {},
	".kdbx":     {},
	".pkcs12":   {},
	".ovpn":     {},
	".env":      {},
}

var unexpectedBinaryExtensions = map[string]struct{}{
	".exe":   {},
	".dll":   {},
	".so":    {},
	".dylib": {},
}

type customScanner struct {
	cfg Config
}

func newCustomScanner(cfg Config) *customScanner {
	return &customScanner{cfg: cfg}
}

func (s *customScanner) Name() string {
	return string(ScannerCustom)
}

func (s *customScanner) Version(context.Context) (string, error) {
	return customScannerVersion, nil
}

func (s *customScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	runID, err := domain.NewID()
	if err != nil {
		return ScannerOutcome{}, err
	}

	run := domain.ScanRun{
		ID:             runID,
		ProposalID:     req.ProposalID,
		ArtifactID:     req.ArtifactID,
		Scanner:        s.Name(),
		ScannerVersion: customScannerVersion,
		Status:         domain.ScanStatusRunning,
		StartedAt:      startedAt,
	}

	if inv == nil {
		var walkErr error
		inv, walkErr = WalkWorkspace(req.TargetDir)
		if walkErr != nil {
			completedAt := time.Now().UTC().Truncate(time.Microsecond)
			run.CompletedAt = &completedAt
			finalizeScanRunCoverage(&run, nil, 0, 1, []string{"workspace_walk_failed"}, true, false, nil)
			return ScannerOutcome{ScanRun: run, FailureReason: "walk_error"}, walkErr
		}
	}

	redactor := NewRedactor(req.ExtraSecrets...)
	var (
		findings   []domain.Finding
		rawSecrets []string
		examined   int
		skipped    int
		reasons    []string
	)

	maxInspect := s.cfg.MaxFileInspectBytes
	if maxInspect <= 0 {
		maxInspect = defaultMaxFileInspectBytes
	}

	for _, entry := range inv.Files {
		if ctx.Err() != nil {
			completedAt := time.Now().UTC().Truncate(time.Microsecond)
			run.CompletedAt = &completedAt
			finalizeScanRunCoverage(&run, inv, examined, skipped, append(reasons, "scanner_timeout"), false, true, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "timeout",
			}, ctx.Err()
		}

		examined++

		if isRestrictedSecretFile(entry.RelPath) {
			harvested, digest, readErr := harvestRestrictedFileSecrets(entry.AbsPath, maxInspect)
			if readErr != nil {
				skipped++
				reasons = append(reasons, "unreadable:"+entry.RelPath)
				continue
			}
			if entry.Size > maxInspect {
				skipped++
				reasons = append(reasons, "oversized_skipped:"+entry.RelPath)
			}
			rawSecrets = append(rawSecrets, harvested...)
			redactor.AddSecrets(harvested...)

			fp := ComputeFingerprint(string(ScannerCustom), "custom.restricted-secret-file", entry.RelPath, 0, 0, digest)
			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerCustom),
				Category:    "SECRET",
				Severity:    domain.SeverityCritical,
				RuleID:      "custom.restricted-secret-file",
				Path:        entry.RelPath,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     fmt.Sprintf("Restricted secret or key artifact detected at %s", entry.RelPath),
				Redacted:    true,
				Metadata: map[string]any{
					"tool": string(ScannerCustom),
					"rule": "restricted-secret-file",
				},
			})
			continue
		}

		// Inspect binary executable signatures first, then scan text content for credential patterns.
		isBinExec, headerDigest, inspectErr := detectBinaryExecutable(entry.AbsPath, entry.RelPath)
		if inspectErr != nil {
			skipped++
			reasons = append(reasons, "unreadable:"+entry.RelPath)
			continue
		}
		if isBinExec {
			fp := ComputeFingerprint(string(ScannerCustom), "custom.unexpected-binary", entry.RelPath, 0, 0, headerDigest)
			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerCustom),
				Category:    "POLICY",
				Severity:    domain.SeverityHigh,
				RuleID:      "custom.unexpected-binary",
				Path:        entry.RelPath,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     fmt.Sprintf("Unexpected binary executable detected at %s", entry.RelPath),
				Redacted:    true,
				Metadata: map[string]any{
					"tool": string(ScannerCustom),
					"rule": "unexpected-binary",
				},
			})
			continue
		}

		if entry.Size > 0 && entry.Size <= maxInspect {
			contentFindings, contentSecrets, scanErr := scanFileCredentialPatterns(entry.AbsPath, entry.RelPath)
			if scanErr != nil {
				skipped++
				reasons = append(reasons, "unreadable:"+entry.RelPath)
				continue
			}
			if len(contentSecrets) > 0 {
				rawSecrets = append(rawSecrets, contentSecrets...)
				redactor.AddSecrets(contentSecrets...)
			}
			findings = append(findings, contentFindings...)
		} else if entry.Size > maxInspect {
			skipped++
			reasons = append(reasons, "oversized_skipped:"+entry.RelPath)
		}
	}

	for i := range findings {
		if err := redactor.FinalizeFinding(&findings[i], run.ID); err != nil {
			completedAt := time.Now().UTC().Truncate(time.Microsecond)
			run.CompletedAt = &completedAt
			finalizeScanRunCoverage(&run, inv, examined, skipped, append(reasons, "redaction_validation_failed"), true, false, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "redaction_error",
			}, err
		}
	}

	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	run.CompletedAt = &completedAt
	finalizeScanRunCoverage(&run, inv, examined, skipped, reasons, false, false, redactor)

	failureReason := ""
	if !run.IsCleanComplete() {
		failureReason = "files_skipped"
	}
	return ScannerOutcome{
		ScanRun:       run,
		Findings:      findings,
		FailureReason: failureReason,
		rawSecrets:    rawSecrets,
	}, nil
}

func isRestrictedSecretFile(relPath string) bool {
	norm := strings.ToLower(filepath.ToSlash(relPath))
	parts := strings.Split(norm, "/")
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := restrictedPathSegments[parts[i]]; ok {
			return true
		}
	}

	base := filepath.Base(norm)
	if _, ok := restrictedEnvAllowlist[base]; ok {
		return false
	}
	if _, ok := restrictedExactFilenames[base]; ok {
		return true
	}
	if strings.HasPrefix(base, ".env.") {
		return true
	}
	if !strings.HasSuffix(base, ".pub") {
		if strings.HasPrefix(base, "id_rsa") ||
			strings.HasPrefix(base, "id_ed25519") ||
			strings.HasPrefix(base, "id_ecdsa") ||
			strings.HasPrefix(base, "id_dsa") {
			return true
		}
	}
	if strings.HasPrefix(base, "credentials.") || base == "credentials" {
		return true
	}
	if strings.HasPrefix(base, "service-account") && strings.HasSuffix(base, ".json") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(base))
	_, restrictedExt := restrictedSecretExtensions[ext]
	return restrictedExt
}

// harvestRestrictedFileSecrets reads bounded content from a restricted file strictly to register
// secret lines with Redactor and compute a content digest; the raw bytes are never emitted.
func harvestRestrictedFileSecrets(absPath string, maxBytes int64) ([]string, string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	if maxBytes <= 0 {
		maxBytes = defaultMaxFileInspectBytes
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return nil, "", err
	}
	digest := domain.SHA256Hex(data)

	var secrets []string
	rawText := string(data)
	lfText := strings.ReplaceAll(rawText, "\r\n", "\n")

	fullTrimmed := strings.TrimSpace(rawText)
	if len(fullTrimmed) > 0 && len(fullTrimmed) <= 16384 && strings.Contains(fullTrimmed, "-----BEGIN ") {
		secrets = append(secrets, fullTrimmed)
	}
	lfTrimmed := strings.TrimSpace(lfText)
	if len(lfTrimmed) > 0 && len(lfTrimmed) <= 16384 && strings.Contains(lfTrimmed, "-----BEGIN ") {
		secrets = append(secrets, lfTrimmed)
	}
	for _, blk := range privateKeyBlockRe.FindAllString(lfText, -1) {
		if len(blk) > 0 && len(blk) <= 65536 {
			secrets = append(secrets, blk)
		}
	}

	inKeyBlock := false
	for _, line := range strings.Split(lfText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "-----BEGIN ") {
			lastBegin := strings.LastIndex(trimmed, "-----BEGIN ")
			lastEnd := strings.LastIndex(trimmed, "-----END ")
			if lastBegin > lastEnd {
				inKeyBlock = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "-----END ") {
			lastBegin := strings.LastIndex(trimmed, "-----BEGIN ")
			lastEnd := strings.LastIndex(trimmed, "-----END ")
			inKeyBlock = lastBegin > lastEnd
			continue
		}
		if !inKeyBlock && strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(trimmed) >= 4 {
			secrets = append(secrets, trimmed)
		}
		if !inKeyBlock {
			cleaned := stripUnquotedInlineComment(trimmed)
			for _, kv := range extractEnvAssignmentValues(cleaned) {
				if len(kv) >= 4 {
					secrets = append(secrets, kv)
				}
			}
		}
	}
	return secrets, digest, nil
}

func detectBinaryExecutable(absPath, relPath string) (bool, string, error) {
	ext := strings.ToLower(filepath.Ext(relPath))
	f, err := os.Open(absPath)
	if err != nil {
		return false, "", err
	}
	defer f.Close()

	var header [256]byte
	n, readErr := io.ReadFull(f, header[:])
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return false, "", readErr
	}
	buf := header[:n]
	digest := domain.SHA256Hex(buf)

	if _, badExt := unexpectedBinaryExtensions[ext]; badExt {
		return true, digest, nil
	}
	if len(buf) < 4 {
		return false, digest, nil
	}

	// ELF magic: 0x7f 'E' 'L' 'F'
	if bytes.HasPrefix(buf, []byte{0x7f, 'E', 'L', 'F'}) {
		return true, digest, nil
	}

	// Mach-O 32/64-bit magic (little & big endian)
	magicBE := binary.BigEndian.Uint32(buf[:4])
	switch magicBE {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
		return true, digest, nil
	case 0xCAFEBABE:
		// Fat Mach-O uses nfat_arch (reasonable small count <= 20), avoiding Java class confusion where minor/major follow.
		if len(buf) >= 8 {
			nArch := binary.BigEndian.Uint32(buf[4:8])
			if nArch >= 1 && nArch <= 20 {
				return true, digest, nil
			}
		}
	}

	// PE/COFF executable: "MZ" header + valid e_lfanew pointing to "PE\x00\x00"
	if buf[0] == 'M' && buf[1] == 'Z' && len(buf) >= 64 {
		peOffset := int64(binary.LittleEndian.Uint32(buf[60:64]))
		if peOffset >= 64 && peOffset <= 4096 {
			if _, seekErr := f.Seek(peOffset, io.SeekStart); seekErr == nil {
				var sig [4]byte
				if _, err := io.ReadFull(f, sig[:]); err == nil && bytes.Equal(sig[:], []byte{'P', 'E', 0, 0}) {
					return true, digest, nil
				}
			}
		}
	}

	return false, digest, nil
}

func scanFileCredentialPatterns(absPath, relPath string) ([]domain.Finding, []string, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// Skip non-text binary data blobs containing NUL bytes in prefix.
	var probe [512]byte
	n, readErr := io.ReadFull(f, probe[:])
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return nil, nil, readErr
	}
	if bytes.IndexByte(probe[:n], 0) >= 0 {
		return nil, nil, nil
	}
	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		return nil, nil, seekErr
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		findings   []domain.Finding
		rawSecrets []string
		lineNo     int
		inPEMBlock bool
		pemBuf     strings.Builder
	)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		rest := trimmed
		if inPEMBlock {
			if endIdx := strings.Index(rest, "-----END "); endIdx >= 0 {
				endLine := rest[endIdx:]
				afterEnd := ""
				if closeRel := strings.Index(endLine[9:], "-----"); closeRel >= 0 {
					endPos := 9 + closeRel + 5
					afterEnd = endLine[endPos:]
					endLine = endLine[:endPos]
				}
				if pemBuf.Len() < 65536 {
					pemBuf.WriteByte('\n')
					pemBuf.WriteString(endLine)
				}
				blockLF := pemBuf.String()
				rawSecrets = append(rawSecrets, blockLF, strings.ReplaceAll(blockLF, "\n", "\r\n"))
				pemBuf.Reset()
				inPEMBlock = false
				rest = afterEnd
			} else {
				if pemBuf.Len() < 65536 {
					pemBuf.WriteByte('\n')
					pemBuf.WriteString(rest)
				}
				if len(rest) >= 6 {
					rawSecrets = append(rawSecrets, rest)
				}
				rest = ""
			}
		}
		for !inPEMBlock && isPrivateKeyBeginLine(rest) {
			beginIdx := strings.Index(rest, "-----BEGIN ")
			if beginIdx < 0 {
				break
			}
			beginPart := rest[beginIdx:]
			if endIdx := strings.Index(beginPart, "-----END "); endIdx >= 0 {
				inlineBlock := beginPart
				afterEnd := ""
				if closeRel := strings.Index(beginPart[endIdx+9:], "-----"); closeRel >= 0 {
					endPos := endIdx + 9 + closeRel + 5
					afterEnd = beginPart[endPos:]
					inlineBlock = beginPart[:endPos]
				}
				if len(inlineBlock) >= 6 {
					rawSecrets = append(rawSecrets, inlineBlock)
				}
				rest = afterEnd
			} else {
				inPEMBlock = true
				pemBuf.Reset()
				pemBuf.WriteString(beginPart)
				rest = ""
			}
		}
		var lineMatches []string
		for _, pat := range secretScrubPatterns {
			matches := pat.FindAllString(line, -1)
			if len(matches) > 0 {
				lineMatches = append(lineMatches, matches...)
			}
		}
		if len(lineMatches) > 0 {
			rawSecrets = append(rawSecrets, lineMatches...)
			fp := ComputeFingerprint(string(ScannerCustom), "custom.credential-pattern", relPath, lineNo, lineNo, lineMatches[0])
			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerCustom),
				Category:    "SECRET",
				Severity:    domain.SeverityCritical,
				RuleID:      "custom.credential-pattern",
				Path:        relPath,
				StartLine:   lineNo,
				EndLine:     lineNo,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     fmt.Sprintf("Redacted credential pattern detected in %s", relPath),
				Redacted:    true,
				Metadata: map[string]any{
					"tool": string(ScannerCustom),
					"rule": "credential-pattern",
				},
			})
		}
	}
	if inPEMBlock && pemBuf.Len() > 0 {
		blockLF := pemBuf.String()
		rawSecrets = append(rawSecrets, blockLF, strings.ReplaceAll(blockLF, "\n", "\r\n"))
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return findings, rawSecrets, nil
}

func isPrivateKeyBeginLine(line string) bool {
	return strings.Contains(line, "-----BEGIN ") &&
		(strings.Contains(line, "PRIVATE KEY-----") || strings.Contains(line, "PRIVATE KEY BLOCK-----"))
}
