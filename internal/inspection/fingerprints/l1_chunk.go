package fingerprints

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	defaultChunkSizeBytes   = 4096
	minNonWhitespaceBytesL1 = 64
)

// L1Chunk represents one deterministic chunk SHA-256 fingerprint for a normalized file.
type L1Chunk struct {
	ChunkIndex   int
	LineStart    int
	LineEnd      int
	ChunkBytes   int
	HashHex      string
	FilePathHash string
}

// normalizeText removes a leading UTF-8 BOM and normalizes CRLF/CR line endings to LF.
func normalizeText(data []byte) string {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	s := string(data)
	if strings.Contains(s, "\r\n") {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	if strings.Contains(s, "\r") {
		s = strings.ReplaceAll(s, "\r", "\n")
	}
	return s
}

func countNonWhitespaceBytes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
		default:
			n++
		}
	}
	return n
}

// ExtractL1Chunks computes deterministic exact-chunk SHA-256 hashes over normalized text.
// Files with fewer than 64 non-whitespace bytes or binary NUL bytes in prefix are skipped.
func ExtractL1Chunks(relPath string, data []byte, chunkSizeBytes int) []L1Chunk {
	if chunkSizeBytes <= 0 {
		chunkSizeBytes = defaultChunkSizeBytes
	}
	if looksBinary(data) {
		return nil
	}
	norm := normalizeText(data)
	if countNonWhitespaceBytes(norm) < minNonWhitespaceBytesL1 {
		return nil
	}
	filePathHash := domain.SHA256Hex([]byte(filepath.ToSlash(relPath)))

	if len(norm) <= chunkSizeBytes {
		totalLines := strings.Count(norm, "\n") + 1
		if strings.HasSuffix(norm, "\n") && totalLines > 1 {
			totalLines--
		}
		return []L1Chunk{
			{
				ChunkIndex:   0,
				LineStart:    1,
				LineEnd:      max(totalLines, 1),
				ChunkBytes:   len(norm),
				HashHex:      sha256HexString(norm),
				FilePathHash: filePathHash,
			},
		}
	}

	// Split preserving trailing newline byte on each line for exact byte-slice reconstruction.
	rawLines := strings.SplitAfter(norm, "\n")
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	if len(rawLines) == 0 {
		return nil
	}

	stepTarget := max(chunkSizeBytes/2, 1)

	chunks := make([]L1Chunk, 0, len(norm)/stepTarget+1)
	chunkIdx := 0
	lineIdx := 0
	for lineIdx < len(rawLines) {
		lineLen := len(rawLines[lineIdx])
		if lineLen > chunkSizeBytes {
			// Single ultra-long line fallback (e.g. minified JS/JSON): byte-window chunks.
			lineStr := rawLines[lineIdx]
			lineNum := lineIdx + 1
			for off := 0; off < len(lineStr); {
				end := off + chunkSizeBytes
				if end > len(lineStr) {
					end = len(lineStr)
				}
				seg := lineStr[off:end]
				if countNonWhitespaceBytes(seg) >= minNonWhitespaceBytesL1 {
					chunks = append(chunks, L1Chunk{
						ChunkIndex:   chunkIdx,
						LineStart:    lineNum,
						LineEnd:      lineNum,
						ChunkBytes:   len(seg),
						HashHex:      sha256HexString(seg),
						FilePathHash: filePathHash,
					})
					chunkIdx++
				}
				if end == len(lineStr) {
					break
				}
				off += stepTarget
			}
			lineIdx++
			continue
		}

		var buf strings.Builder
		buf.Grow(chunkSizeBytes)
		startLine := lineIdx + 1
		endLineIdx := lineIdx
		for endLineIdx < len(rawLines) {
			nextLen := len(rawLines[endLineIdx])
			if buf.Len() > 0 && buf.Len()+nextLen > chunkSizeBytes {
				break
			}
			buf.WriteString(rawLines[endLineIdx])
			endLineIdx++
		}
		chunkStr := buf.String()
		if countNonWhitespaceBytes(chunkStr) >= minNonWhitespaceBytesL1 {
			chunks = append(chunks, L1Chunk{
				ChunkIndex:   chunkIdx,
				LineStart:    startLine,
				LineEnd:      endLineIdx,
				ChunkBytes:   len(chunkStr),
				HashHex:      sha256HexString(chunkStr),
				FilePathHash: filePathHash,
			})
			chunkIdx++
		}

		if endLineIdx >= len(rawLines) {
			break
		}

		advanced := 0
		nextIdx := lineIdx
		for nextIdx < endLineIdx && advanced < stepTarget {
			advanced += len(rawLines[nextIdx])
			nextIdx++
		}
		if nextIdx == lineIdx {
			nextIdx++
		}
		lineIdx = nextIdx
	}

	return chunks
}

func sha256HexString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func isDisallowedControlByte(b byte) bool {
	return b == 0 || (b >= 0x01 && b <= 0x08) || (b >= 0x0e && b <= 0x1f) || b == 0x7f
}

func isInspectionStrippedControlByte(b byte) bool {
	return isDisallowedControlByte(b) || b == 0x0b || b == 0x0c
}

func hasDisallowedControlBytes(data []byte) bool {
	for _, b := range data {
		if isDisallowedControlByte(b) {
			return true
		}
	}
	return false
}

func stripDisallowedControlBytes(data []byte) []byte {
	if !hasDisallowedControlBytes(data) {
		return data
	}
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if !isDisallowedControlByte(b) {
			out = append(out, b)
		}
	}
	return out
}

func stripControlBytesForInspection(data []byte) []byte {
	hasCtrl := false
	for _, b := range data {
		if isInspectionStrippedControlByte(b) {
			hasCtrl = true
			break
		}
	}
	if !hasCtrl {
		return data
	}
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if !isInspectionStrippedControlByte(b) {
			out = append(out, b)
		}
	}
	return out
}

func isVisibleASCII(b byte) bool {
	return b >= 0x21 && b <= 0x7e
}

func hasSuspiciousVerticalControlInterleaving(data []byte) bool {
	ctrlCount := 0
	midTokenCount := 0
	for i, b := range data {
		if b != 0x0b && b != 0x0c {
			continue
		}
		ctrlCount++
		if (i > 0 && isVisibleASCII(data[i-1])) || (i+1 < len(data) && isVisibleASCII(data[i+1])) {
			midTokenCount++
		}
	}
	return midTokenCount >= 2 || (ctrlCount >= 4 && ctrlCount*100 >= len(data))
}

func looksBinary(data []byte) bool {
	return hasDisallowedControlBytes(data)
}
