package inspection

import (
	"fmt"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

// ComputeFingerprint derives a deterministic SHA-256 hex fingerprint without exposing raw match material.
func ComputeFingerprint(scanner, ruleID, relPath string, startLine, endLine int, matchMaterial string) string {
	materialDigest := domain.SHA256Hex([]byte(matchMaterial))
	canonical := fmt.Sprintf(
		"%s\x00%s\x00%s\x00%d\x00%d\x00%s",
		strings.TrimSpace(scanner),
		strings.TrimSpace(ruleID),
		strings.TrimSpace(relPath),
		startLine,
		endLine,
		materialDigest,
	)
	return domain.SHA256Hex([]byte(canonical))
}

// ComputeEvidenceID derives a deterministic grounded evidence identifier matching ^finding_[A-Za-z0-9_-]+$.
func ComputeEvidenceID(scanner, category, ruleID, relPath string, startLine, endLine int, fingerprint string) string {
	canonical := fmt.Sprintf(
		"%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s",
		strings.TrimSpace(scanner),
		strings.TrimSpace(category),
		strings.TrimSpace(ruleID),
		strings.TrimSpace(relPath),
		startLine,
		endLine,
		strings.TrimSpace(fingerprint),
	)
	digest := domain.SHA256Hex([]byte(canonical))
	return fmt.Sprintf("finding_%s_%s", sanitizeScannerSlug(scanner), digest[:16])
}

func sanitizeScannerSlug(scanner string) string {
	s := strings.ToLower(strings.TrimSpace(scanner))
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}
