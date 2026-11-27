package fingerprints

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"container/heap"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"math/big"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
)

const (
	defaultArchiveMaxDepth        = 4
	defaultArchiveMaxEntries      = 512
	defaultArchiveMaxEntryBytes   = 4 << 20  // 4 MiB
	defaultArchiveMaxTotalBytes   = 16 << 20 // 16 MiB
	maxDecodedSegmentBytes        = 2 << 20  // 2 MiB
	maxDecodedTotalPerFile        = 32 << 20 // 32 MiB
	maxDecodeRecursionDepth       = 3
	maxEncodedCandidates          = 2048
	maxInlineCommentSkipBytes     = 256 * 1024
	minEntropyBytes               = 256
	entropyWindowBytes            = 4096
	entropyWindowStep             = 2048
	entropyMaxWindows             = 4096
	entropyThreshold              = 7.2
	entropyThresholdHighPrintable = 7.5
)

var (
	pdfObjRe       = regexp.MustCompile(`(?m)^[ \t]*\d+[ \t]+\d+[ \t]+obj\b`)
	pdfEndObjRe    = regexp.MustCompile(`(?m)(?:^|[ \t])endobj\b`)
	pdfStartXrefRe = regexp.MustCompile(`(?m)^[ \t]*(?:startxref|xref)\b`)
	pdfEOFRe       = regexp.MustCompile(`(?m)^[ \t]*%%EOF[ \t]*$`)
)

type credentialRule struct {
	slug string
	re   *regexp.Regexp
}

var concealmentCredentialRules = []credentialRule{
	{slug: "private-key-block", re: regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]{16,}?-----END\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----`)},
	{slug: "github-token", re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`)},
	{slug: "github-fine-grained-pat", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`)},
	{slug: "gitlab-pat", re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{8,}`)},
	{slug: "aws-access-key-id", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{slug: "api-sk-token", re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{10,}`)},
	{slug: "slack-token", re: regexp.MustCompile(`\bxox[bp]-[A-Za-z0-9-]{8,}`)},
	{slug: "jwt-token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)},
	{slug: "x-access-token-url", re: regexp.MustCompile(`(?i)\bx-access-token:[^\s@'"]{6,}`)},
}

type archiveBudget struct {
	MaxDepth              int
	MaxEntries            int
	MaxEntryInflatedBytes int64
	MaxTotalInflatedBytes int64
	EntriesSeen           int
	TotalInflated         int64
}

func newDefaultArchiveBudget() *archiveBudget {
	return &archiveBudget{
		MaxDepth:              defaultArchiveMaxDepth,
		MaxEntries:            defaultArchiveMaxEntries,
		MaxEntryInflatedBytes: defaultArchiveMaxEntryBytes,
		MaxTotalInflatedBytes: defaultArchiveMaxTotalBytes,
	}
}

type inspectedBuffer struct {
	VirtualPath    string
	Data           []byte
	InArchive      bool
	InEncoded      bool
	ExtractedMedia bool
}

type l4FileResult struct {
	Findings       []domain.Finding
	InspectBuffers []inspectedBuffer
	ExtraSkipped   int
	SkippedReasons []string
	seenCreds      map[string]struct{}
}

func inspectFileL4(ctx context.Context, relPath string, data []byte) l4FileResult {
	res := l4FileResult{}
	budget := newDefaultArchiveBudget()
	decodeRemaining := int64(maxDecodedTotalPerFile)
	inspectRecursiveL4(ctx, relPath, data, 0, 0, false, false, budget, &decodeRemaining, &res)
	return res
}

func inspectRecursiveL4(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	inspectRecursiveL4Opts(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, false, false, budget, decodeRemaining, res)
}

func inspectRecursiveL4Opts(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	exemptBinaryAssetEntropy bool,
	extractedMedia bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if ctx.Err() != nil {
		return
	}
	if len(data) == 0 {
		return
	}

	// Only collect leaf text/source buffers for L1/L2/L3 unless archive/binary needs stripping.
	var (
		magicKind      string
		magicValid     bool
		spoofPrefixLen int
		pdfRes         pdfValidationResult
	)
	if bytes.HasPrefix(data, []byte("%PDF-1.")) || bytes.HasPrefix(data, []byte("%PDF-2.")) {
		if isValidPDFHeaderSyntax(data) {
			pdfRes = validateAndInspectPDFStreams(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			if pdfRes.valid || pdfRes.bombed {
				magicKind = "pdf"
				magicValid = true
			} else {
				magicKind = "pdf_invalid"
				magicValid = false
				spoofPrefixLen = 8
			}
		} else {
			magicKind = "pdf_invalid"
			magicValid = false
			spoofPrefixLen = 8
		}
	} else {
		magicKind, magicValid, spoofPrefixLen = detectMagicKind(data)
	}
	ext := strings.ToLower(filepath.Ext(virtualPath))

	// L4d: Structural magic-byte mismatch check.
	mismatchDetected := false
	if mismatch, reasonKind := checkMagicExtensionMismatch(ext, data, magicKind, magicValid); mismatch {
		mismatchDetected = true
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.magic-byte-mismatch",
			domain.SeverityHigh,
			virtualPath,
			fmt.Sprintf("structural magic-byte mismatch detected (%s)", reasonKind),
			map[string]any{
				"layer":          "L4_CONCEALMENT",
				"technique":      "magic_byte_mismatch",
				"detected_magic": reasonKind,
				"file_ext":       ext,
			},
			reasonKind,
		))
	}

	// If disguised binary header (e.g. PNG prefix on Go source) was stripped, inspect embedded payload.
	if mismatchDetected && spoofPrefixLen > 0 && len(data) > spoofPrefixLen {
		embedded := data[spoofPrefixLen:]
		if !looksBinary(embedded) {
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    virtualPath + "#unwrapped",
				Data:           embedded,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: extractedMedia,
			})
			inspectDecodedOrUnwrapped(ctx, virtualPath+"#unwrapped", embedded, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			return
		}
	}

	// L4c: Bounded archive inspection when file is archive by extension or verified archive magic.
	isArchiveExt := isArchiveExtension(virtualPath)
	isArchiveMagic := magicKind == "zip" || magicKind == "gzip" || magicKind == "tar"
	if isArchiveExt || isArchiveMagic {
		if archiveDepth >= budget.MaxDepth {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("archive_depth_exceeded:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.archive-limit-exceeded",
				domain.SeverityCritical,
				virtualPath,
				"nested archive exceeded maximum inspection depth",
				map[string]any{
					"layer":     "L4_CONCEALMENT",
					"technique": "archive_depth_exceeded",
					"max_depth": budget.MaxDepth,
				},
				"depth_exceeded",
			))
			return
		}

		if isArchiveMagic || isArchiveExt {
			handled := inspectArchiveBuffer(ctx, virtualPath, data, magicKind, archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
			if handled {
				return
			}
		}
	}

	// Register regular text/source buffer or extracted printable text runs for L1/L2/L3/L4b scanning.
	var textBufForL4b []byte
	utf16Decoded := false
	isMediaOrArchive := isArchiveExt || isArchiveMagic ||
		magicKind == "png" || magicKind == "jpeg" || magicKind == "gif" ||
		magicKind == "webp" || magicKind == "pdf" || magicKind == "wasm" ||
		magicKind == "elf" || magicKind == "macho" || magicKind == "pe" ||
		magicKind == "icc" || magicKind == "sfnt" || magicKind == "ttc"
	c0Stripped := stripControlBytesForInspection(data)
	if !looksBinary(data) {
		res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
			VirtualPath:    virtualPath,
			Data:           data,
			InArchive:      inArchive,
			InEncoded:      inEncoded,
			ExtractedMedia: extractedMedia,
		})
		if len(c0Stripped) != len(data) && len(c0Stripped) > 0 {
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    virtualPath + "#ctrl_stripped",
				Data:           c0Stripped,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: extractedMedia,
			})
			textBufForL4b = c0Stripped
		} else {
			textBufForL4b = data
		}
	} else if !isMediaOrArchive {
		if decoded, ok := decodeUTF16Text(data); ok {
			utf16Decoded = true
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    virtualPath,
				Data:           decoded,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: extractedMedia,
			})
			textBufForL4b = decoded
		} else {
			if len(c0Stripped) > 0 && !looksBinary(c0Stripped) &&
				(isTextOrSourceExt(ext) || (len(c0Stripped) >= 64 && utf8.Valid(c0Stripped) && (hasHighPrintableAscii(c0Stripped) || hasSignificantPrintableText(c0Stripped)))) {
				res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
					VirtualPath:    virtualPath,
					Data:           c0Stripped,
					InArchive:      inArchive,
					InEncoded:      inEncoded,
					ExtractedMedia: extractedMedia,
				})
				textBufForL4b = c0Stripped
			} else {
				extracted := extractPrintableTextRuns(data, 32)
				if len(c0Stripped) > 0 && len(c0Stripped) != len(data) {
					if extractedStripped := extractPrintableTextRuns(c0Stripped, 32); len(extractedStripped) > len(extracted) {
						extracted = extractedStripped
					}
				}
				if len(extracted) > 0 {
					res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
						VirtualPath:    virtualPath + "#printable",
						Data:           extracted,
						InArchive:      inArchive,
						InEncoded:      inEncoded,
						ExtractedMedia: true,
					})
					textBufForL4b = extracted
				}
			}
		}
	} else {
		extracted := extractPrintableTextRuns(data, 32)
		if !magicValid {
			if len(c0Stripped) > 0 && len(c0Stripped) != len(data) {
				if extractedStripped := extractPrintableTextRuns(c0Stripped, 32); len(extractedStripped) > len(extracted) {
					extracted = extractedStripped
				}
			}
		}
		if len(extracted) > 0 {
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    virtualPath + "#printable",
				Data:           extracted,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: true,
			})
			textBufForL4b = extracted
		}
	}

	// If an encoded/decoded payload is a bounded raw zlib stream, inflate and inspect recursively.
	if inEncoded && !isMediaOrArchive && decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
		maxZ := min(int64(maxDecodedSegmentBytes), *decodeRemaining)
		if inflated, ok := tryDecompressZlibBounded(data, maxZ); ok {
			*decodeRemaining -= int64(len(inflated))
			inspectRecursiveL4(ctx, virtualPath+"#zlib", inflated, archiveDepth, decodeDepth+1, inArchive, true, budget, decodeRemaining, res)
		}
	}

	// Inspect valid WASM Custom (secID == 0) & Data (secID == 11) sections so they are never blanket-exempted.
	if magicKind == "wasm" && magicValid {
		inspectWASMCustomSections(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Inspect valid PNG non-IDAT ancillary chunks (iCCP, zTXt, iTXt, tEXt, eXIf, private chunks).
	if magicKind == "png" && magicValid {
		inspectPNGChunks(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Inspect valid JPEG metadata/comment/app/table segments (APP0..APP15, COM, DQT, DHT).
	if magicKind == "jpeg" && magicValid {
		inspectJPEGMetadataSegments(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Inspect valid WebP metadata chunks (EXIF, XMP , ICCP).
	if magicKind == "webp" && magicValid {
		inspectWebPMetadataChunks(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Inspect non-stream bytes of valid PDF documents (comments, object dicts, post-fake-endstream regions).
	if magicKind == "pdf" && magicValid {
		inspectPDFNonStreamBytes(ctx, virtualPath, data, pdfRes.streamSpans, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Inspect standalone validated ICC profile tags/strings (with ExtractedMedia=true).
	if magicKind == "icc" && magicValid {
		inspectValidatedICCProfile(ctx, virtualPath, "#icc_text", data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}

	// Unconditional deduped credential checks across raw, C0-stripped, L4b text, and lossy UTF-16 buffers.
	emitCredentialFindings(virtualPath, data, res)
	if len(c0Stripped) > 0 && !bytes.Equal(c0Stripped, data) {
		emitCredentialFindings(virtualPath, c0Stripped, res)
	}
	if len(textBufForL4b) > 0 && !bytes.Equal(textBufForL4b, data) && !bytes.Equal(textBufForL4b, c0Stripped) {
		emitCredentialFindings(virtualPath, textBufForL4b, res)
	}
	if !isMediaOrArchive && looksBinary(data) && !utf16Decoded && len(data) >= 16 {
		for _, lossyBuf := range extractLossyUTF16ForCredentials(data) {
			emitCredentialFindings(virtualPath, lossyBuf, res)
		}
	}

	// L4a: High Shannon entropy (exempting structurally valid benign compressed/media formats and validated PDF assets).
	if !exemptBinaryAssetEntropy && !isExemptFromEntropy(magicKind, magicValid) {
		if ent, flagged := checkHighEntropy(data); flagged {
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.high-entropy",
				domain.SeverityHigh,
				virtualPath,
				"high-entropy payload indicative of encrypted or obfuscated data",
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "high_entropy",
					"shannon_bits":  math.Round(ent*1000) / 1000,
					"payload_bytes": len(data),
				},
				fmt.Sprintf("entropy:%.3f:%d", ent, len(data)),
			))
		} else if !isMediaOrArchive && !utf16Decoded && !isValidUTF16Text(data) {
			emittedL4aEntropy := false
			allowPrintable := !isTextOrSourceExt(ext) && !hasLowercaseOrNewline(data)
			emitL4aConcealed := func(technique, fpPrefix string, ent float64, sz int) {
				emittedL4aEntropy = true
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.high-entropy",
					domain.SeverityHigh,
					virtualPath,
					technique,
					map[string]any{
						"layer":         "L4_CONCEALMENT",
						"technique":     "high_entropy",
						"shannon_bits":  math.Round(ent*1000) / 1000,
						"payload_bytes": sz,
					},
					fmt.Sprintf("%s:%.3f:%d", fpPrefix, ent, sz),
				))
			}
			if isBitAgnosticIncompressibleHighEntropy(data, allowPrintable) {
				ent, _ := shannonEntropyAndPrintable(data)
				emitL4aConcealed("high-entropy incompressible bit-packed payload indicative of encrypted or obfuscated data", "bit_agnostic_entropy", ent, len(data))
			}
			if !emittedL4aEntropy && len(c0Stripped) >= minEntropyBytes && len(c0Stripped) < len(data)*9/10 {
				if ent, c0Flagged := checkHighEntropy(c0Stripped); c0Flagged {
					emitL4aConcealed("high-entropy C0-diluted payload indicative of encrypted or obfuscated data", "stripped_entropy", ent, len(c0Stripped))
				} else if isBitAgnosticIncompressibleHighEntropy(c0Stripped, allowPrintable) {
					ent, _ := shannonEntropyAndPrintable(c0Stripped)
					emitL4aConcealed("high-entropy C0-diluted bit-packed payload indicative of encrypted or obfuscated data", "stripped_bit_entropy", ent, len(c0Stripped))
				}
			}
			if !emittedL4aEntropy {
				if collapsed := collapseRepeatedBytes(data, 16); len(collapsed) >= minEntropyBytes && len(collapsed) < len(data)*9/10 {
					if ent, colFlagged := checkHighEntropy(collapsed); colFlagged {
						emitL4aConcealed("high-entropy repeat-diluted payload indicative of encrypted or obfuscated data", "collapsed_entropy", ent, len(collapsed))
					} else if isBitAgnosticIncompressibleHighEntropy(collapsed, allowPrintable) {
						ent, _ := shannonEntropyAndPrintable(collapsed)
						emitL4aConcealed("high-entropy repeat-diluted bit-packed payload indicative of encrypted or obfuscated data", "collapsed_bit_entropy", ent, len(collapsed))
					}
				}
			}
			if !emittedL4aEntropy {
				if pCollapsed := collapseRepeatedPeriodic(data, 32, 4); len(pCollapsed) >= minEntropyBytes && len(pCollapsed) < len(data)*9/10 {
					if checkMaxEntWindowIncompressible(pCollapsed, entropyThreshold) || isBitAgnosticIncompressibleHighEntropy(pCollapsed, allowPrintable) {
						ent, _ := shannonEntropyAndPrintable(pCollapsed)
						emitL4aConcealed("high-entropy periodic-diluted payload indicative of encrypted or obfuscated data", "periodic_collapsed_entropy", ent, len(pCollapsed))
					}
				}
			}
			if !emittedL4aEntropy && hasConstantLanePlusHighEntResidual(data) {
				emittedL4aEntropy = true
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.high-entropy",
					domain.SeverityHigh,
					virtualPath,
					"high-entropy lane-interleaved payload indicative of encrypted or obfuscated data",
					map[string]any{
						"layer":         "L4_CONCEALMENT",
						"technique":     "high_entropy",
						"shannon_bits":  7.2,
						"payload_bytes": len(data),
					},
					fmt.Sprintf("lane_interleaved_entropy:%d", len(data)),
				))
			}
			if !emittedL4aEntropy {
				if dom, ok := stripDominantByteIfOver(data, 20); ok && len(dom) >= minEntropyBytes {
					if checkMaxEntWindowIncompressible(dom, entropyThreshold) || isBitAgnosticIncompressibleHighEntropy(dom, allowPrintable) {
						ent, _ := shannonEntropyAndPrintable(dom)
						emitL4aConcealed("high-entropy byte-diluted payload indicative of encrypted or obfuscated data", "dom_stripped_entropy", ent, len(dom))
					}
				}
			}
			if !emittedL4aEntropy && isTopKPadDilutedHighEntropy(data, allowPrintable) {
				ent, _ := shannonEntropyAndPrintable(data)
				emitL4aConcealed("high-entropy pad-diluted payload indicative of encrypted or obfuscated data", "topk_diluted_entropy", ent, len(data))
			}
		}
	}

	// L4b: Base64 & hex encoded payload decoding + bounded recursive inspection.
	if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 && len(textBufForL4b) > 0 {
		inspectEncodedPayloads(ctx, virtualPath, textBufForL4b, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
	}
}

func inspectDecodedOrUnwrapped(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	emitCredentialFindings(virtualPath, data, res)
	if ent, flagged := checkHighEntropy(data); flagged {
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.high-entropy",
			domain.SeverityHigh,
			virtualPath,
			"high-entropy unwrapped payload detected",
			map[string]any{
				"layer":         "L4_CONCEALMENT",
				"technique":     "high_entropy",
				"shannon_bits":  math.Round(ent*1000) / 1000,
				"payload_bytes": len(data),
			},
			fmt.Sprintf("unwrapped_entropy:%.3f:%d", ent, len(data)),
		))
	}
	if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
		stripped := stripControlBytesForInspection(data)
		if !looksBinary(data) {
			if len(stripped) != len(data) && len(stripped) > 0 {
				emitCredentialFindings(virtualPath, stripped, res)
				inspectEncodedPayloads(ctx, virtualPath, stripped, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
			} else {
				inspectEncodedPayloads(ctx, virtualPath, data, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
			}
		} else if len(stripped) > 0 && !looksBinary(stripped) {
			emitCredentialFindings(virtualPath, stripped, res)
			inspectEncodedPayloads(ctx, virtualPath, stripped, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
		}
	}
}

func inspectEncodedPayloads(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	candidates := extractEncodedCandidates(data)
	for idx, cand := range candidates {
		if ctx.Err() != nil || *decodeRemaining <= 0 {
			break
		}
		if int64(len(cand.decoded)) > maxDecodedSegmentBytes || int64(len(cand.decoded)) > *decodeRemaining {
			continue
		}
		*decodeRemaining -= int64(len(cand.decoded))

		subPath := fmt.Sprintf("%s#%s[%d]", virtualPath, cand.kind, idx)
		beforeFindings := len(res.Findings)
		beforeBuffers := len(res.InspectBuffers)
		beforeSkipped := res.ExtraSkipped

		inspectRecursiveL4(ctx, subPath, cand.decoded, archiveDepth, decodeDepth+1, inArchive, true, budget, decodeRemaining, res)

		// Determine whether the decoded buffer actually contains anything actionable (secrets, archive,
		// executable magic, high entropy, or readable text that L1/L2/L3 will inspect).
		// Note: L1/L2/L3 corpus hits for subPath will be checked by Engine.Analyze; if L1/L2/L3 matches
		// on an InEncoded buffer, Engine.Analyze ALSO emits ip.l4.encoded-payload if not already emitted!
		addedFindings := len(res.Findings) > beforeFindings || res.ExtraSkipped > beforeSkipped
		if addedFindings {
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.encoded-payload",
				domain.SeverityHigh,
				virtualPath,
				fmt.Sprintf("concealed %s-encoded payload detected", cand.kind),
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "encoded_payload",
					"encoding":      cand.kind,
					"decoded_bytes": len(cand.decoded),
				},
				fmt.Sprintf("%s:%d:%s", cand.kind, idx, domain.SHA256Hex(cand.decoded)),
			))
		} else if len(res.InspectBuffers) == beforeBuffers && isExecutableOrArchiveMagic(cand.decoded) {
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.encoded-payload",
				domain.SeverityHigh,
				virtualPath,
				fmt.Sprintf("concealed %s-encoded binary payload detected", cand.kind),
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "encoded_payload",
					"encoding":      cand.kind,
					"decoded_bytes": len(cand.decoded),
				},
				fmt.Sprintf("%s:%d:%s", cand.kind, idx, domain.SHA256Hex(cand.decoded)),
			))
		}
	}
}

type encodedCandidate struct {
	kind         string // "b64" | "hex"
	decoded      []byte
	priorityTier int // 2 = cred/exec/arch/magic/zlib/highEnt, 1 = code language, 0 = plain text
	seq          int
}

type encodedCandidateHeap []encodedCandidate

func (h encodedCandidateHeap) Len() int { return len(h) }
func (h encodedCandidateHeap) Less(i, j int) bool {
	if h[i].priorityTier != h[j].priorityTier {
		return h[i].priorityTier < h[j].priorityTier
	}
	if len(h[i].decoded) != len(h[j].decoded) {
		return len(h[i].decoded) < len(h[j].decoded)
	}
	return h[i].seq > h[j].seq
}
func (h encodedCandidateHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *encodedCandidateHeap) Push(x any)   { *h = append(*h, x.(encodedCandidate)) }
func (h *encodedCandidateHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func allSameByteString(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func leadingPeriodicPrefixLen(s string) int {
	best := 0
	for period := 1; period <= 4; period++ {
		if len(s) < period*4 {
			continue
		}
		unit := s[:period]
		pos := period
		for pos+period <= len(s) && s[pos:pos+period] == unit {
			pos += period
		}
		if pos >= period*4 && pos > best {
			best = pos
		}
	}
	return best
}

func collapseRepeatedBytes(b []byte, minRun int) []byte {
	if len(b) == 0 || minRun <= 1 {
		return b
	}
	out := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		j := i + 1
		for j < len(b) && b[j] == b[i] {
			j++
		}
		run := j - i
		if run >= minRun {
			out = append(out, b[i])
		} else {
			out = append(out, b[i:j]...)
		}
		i = j
	}
	return out
}

func collapseRepeatedPeriodic(b []byte, maxPeriod, minRepeats int) []byte {
	if len(b) == 0 || maxPeriod < 1 || minRepeats < 2 || len(b) < minRepeats {
		return b
	}
	out := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		matchedPeriod := 0
		matchedEnd := 0
		for p := 1; p <= maxPeriod; p++ {
			reqRepeats := minRepeats
			if p*reqRepeats < 16 {
				reqRepeats = (16 + p - 1) / p
			}
			if i+p*reqRepeats > len(b) {
				continue
			}
			if b[i+p] != b[i] {
				continue
			}
			unit := b[i : i+p]
			isPeriodic := true
			for r := 1; r < reqRepeats; r++ {
				if !bytes.Equal(b[i+r*p:i+(r+1)*p], unit) {
					isPeriodic = false
					break
				}
			}
			if isPeriodic {
				j := i + p*reqRepeats
				for j < len(b) && b[j] == unit[(j-i)%p] {
					j++
				}
				matchedPeriod = p
				matchedEnd = j
				break
			}
		}
		if matchedPeriod > 0 {
			out = append(out, b[i:i+matchedPeriod]...)
			i = matchedEnd
		} else {
			out = append(out, b[i])
			i++
		}
	}
	return out
}

func stripDominantByteIfOver(b []byte, pct int) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var counts [256]int
	for _, x := range b {
		counts[x]++
	}
	bestByte := byte(0)
	bestCount := 0
	for i, c := range counts {
		if c > bestCount {
			bestCount = c
			bestByte = byte(i)
		}
	}
	if bestCount*100 <= len(b)*pct {
		return nil, false
	}
	out := make([]byte, 0, len(b)-bestCount)
	for _, x := range b {
		if x != bestByte {
			out = append(out, x)
		}
	}
	return out, true
}

func stripTopKBytes(b []byte, maxK, minPerBytePct, minTotalPct int) ([]byte, bool) {
	if len(b) == 0 || maxK <= 0 {
		return nil, false
	}
	var counts [256]int
	for _, x := range b {
		counts[x]++
	}
	type bvCount struct {
		val byte
		cnt int
	}
	var cands [256]bvCount
	nCands := 0
	for i, c := range counts {
		if c*100 >= len(b)*minPerBytePct {
			cands[nCands] = bvCount{val: byte(i), cnt: c}
			nCands++
		}
	}
	if nCands == 0 {
		return nil, false
	}
	sort.Slice(cands[:nCands], func(i, j int) bool {
		if cands[i].cnt != cands[j].cnt {
			return cands[i].cnt > cands[j].cnt
		}
		return cands[i].val < cands[j].val
	})
	if nCands > maxK {
		nCands = maxK
	}
	var stripMask [256]bool
	totalStripped := 0
	for i := 0; i < nCands; i++ {
		stripMask[cands[i].val] = true
		totalStripped += cands[i].cnt
	}
	if totalStripped*100 < len(b)*minTotalPct {
		return nil, false
	}
	out := make([]byte, 0, len(b)-totalStripped)
	for _, x := range b {
		if !stripMask[x] {
			out = append(out, x)
		}
	}
	return out, true
}

func distinctBytesCount(b []byte) int {
	var seen [256]bool
	dist := 0
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			dist++
		}
	}
	return dist
}

func hasLowercaseOrNewline(b []byte) bool {
	for _, x := range b {
		if (x >= 'a' && x <= 'z') || x == '\n' {
			return true
		}
	}
	return false
}

func seqAvgDiff(b []byte) float64 {
	if len(b) < 2 {
		return 0
	}
	var sum uint64
	for i := 1; i < len(b); i++ {
		d := int(b[i]) - int(b[i-1])
		if d < 0 {
			d = -d
		}
		sum += uint64(d)
	}
	return float64(sum) / float64(len(b)-1)
}

func hasHighDeltaEntropy(b []byte) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	winLen := min(len(b), 512)
	checkDelta := func(win []byte) bool {
		if len(win) < 32 {
			return false
		}
		d := make([]byte, len(win)-1)
		for i := 1; i < len(win); i++ {
			d[i-1] = win[i] - win[i-1]
		}
		ent, _ := shannonEntropyAndPrintable(d)
		return ent >= 5.50 && zlibCompressedRatio(d) >= 0.72
	}
	if len(b) <= 512 {
		return checkDelta(b)
	}
	step := 256
	if span := len(b) - winLen; span/step+1 > 512 {
		step = max(span/512, 256)
	}
	lastOff := -1
	for off := 0; off+winLen <= len(b); off += step {
		lastOff = off
		if checkDelta(b[off : off+winLen]) {
			return true
		}
	}
	tailOff := len(b) - winLen
	if tailOff > lastOff && checkDelta(b[tailOff:]) {
		return true
	}
	return false
}

func stripTopKBytesPermille(b []byte, maxK, minPerBytePermille, minTotalPct int) ([]byte, bool) {
	if len(b) == 0 || maxK <= 0 {
		return nil, false
	}
	var counts [256]int
	for _, x := range b {
		counts[x]++
	}
	type bvCount struct {
		val byte
		cnt int
	}
	var cands [256]bvCount
	nCands := 0
	for i, c := range counts {
		if c*1000 >= len(b)*minPerBytePermille {
			cands[nCands] = bvCount{val: byte(i), cnt: c}
			nCands++
		}
	}
	if nCands == 0 {
		return nil, false
	}
	sort.Slice(cands[:nCands], func(i, j int) bool {
		if cands[i].cnt != cands[j].cnt {
			return cands[i].cnt > cands[j].cnt
		}
		return cands[i].val < cands[j].val
	})
	if nCands > maxK {
		nCands = maxK
	}
	var stripMask [256]bool
	totalStripped := 0
	for i := 0; i < nCands; i++ {
		stripMask[cands[i].val] = true
		totalStripped += cands[i].cnt
	}
	if totalStripped*100 < len(b)*minTotalPct {
		return nil, false
	}
	out := make([]byte, 0, len(b)-totalStripped)
	for _, x := range b {
		if !stripMask[x] {
			out = append(out, x)
		}
	}
	return out, true
}

func isBitAgnosticIncompressibleHighEntropy(b []byte, allowPrintable bool) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	checkWin := func(win []byte) bool {
		if len(win) < minEntropyBytes {
			return false
		}
		ent, pr := shannonEntropyAndPrintable(win)
		if ent < 5.75 || (!allowPrintable && pr >= 0.85) || zlibCompressedRatio(win) < 0.88 {
			return false
		}
		if isMonotonicOrSmoothNumericTable(win) {
			return false
		}
		var counts [256]int
		for _, x := range win {
			counts[x]++
		}
		var nz [256]int
		dist := 0
		for _, c := range counts {
			if c > 0 {
				nz[dist] = c
				dist++
			}
		}
		if dist <= 1 || dist > 160 {
			return false
		}
		sort.Slice(nz[:dist], func(i, j int) bool { return nz[i] > nz[j] })
		sum := 0
		k95 := 0
		for k := 0; k < dist; k++ {
			sum += nz[k]
			k95 = k + 1
			if sum*100 >= len(win)*95 {
				break
			}
		}
		if k95 <= 1 || k95 > 136 {
			return false
		}
		return ent/math.Log2(float64(k95)) >= 0.96
	}
	if len(b) <= 1<<20 && checkWin(b) {
		return true
	}
	if len(b) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(b) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(b); off += step {
			lastOff = off
			if checkWin(b[off : off+entropyWindowBytes]) {
				return true
			}
		}
		tailOff := len(b) - entropyWindowBytes
		if tailOff > lastOff && checkWin(b[tailOff:]) {
			return true
		}
	}
	return false
}

func isTopKPadDilutedHighEntropy(b []byte, allowPrintable bool) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	dk, ok := stripTopKBytesPermille(b, 48, 12, 20)
	if !ok || len(dk) < minEntropyBytes {
		return false
	}
	checkWin := func(win []byte) bool {
		if len(win) < minEntropyBytes {
			return false
		}
		ent, pr := shannonEntropyAndPrintable(win)
		if ent < 5.75 || (!allowPrintable && pr >= 0.85) || zlibCompressedRatio(win) < 0.88 {
			return false
		}
		dist := distinctBytesCount(win)
		if dist <= 1 {
			return false
		}
		eta := ent / math.Log2(float64(dist))
		reqEta := 0.982
		if len(win) >= 768 {
			reqEta = 0.965
		}
		if eta < reqEta {
			return false
		}
		return hasHighDeltaEntropy(win)
	}
	if len(dk) <= 1<<20 && checkWin(dk) {
		return true
	}
	if len(dk) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(dk) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(dk); off += step {
			lastOff = off
			if checkWin(dk[off : off+entropyWindowBytes]) {
				return true
			}
		}
		tailOff := len(dk) - entropyWindowBytes
		if tailOff > lastOff && checkWin(dk[tailOff:]) {
			return true
		}
	}
	return false
}

func hasBitAgnosticIncompressible(b []byte, minEnt, minZR float64) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	checkWin := func(win []byte) bool {
		ent, _ := shannonEntropyAndPrintable(win)
		return ent >= minEnt && zlibCompressedRatio(win) >= minZR
	}
	if len(b) <= 1<<20 && checkWin(b) {
		return true
	}
	if len(b) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(b) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(b); off += step {
			lastOff = off
			if checkWin(b[off : off+entropyWindowBytes]) {
				return true
			}
		}
		tailOff := len(b) - entropyWindowBytes
		if tailOff > lastOff && checkWin(b[tailOff:]) {
			return true
		}
	}
	return false
}

func hasLowDistIncompressible(b []byte, maxDist int, minEnt, minZR float64) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	checkWin := func(win []byte) bool {
		if distinctBytesCount(win) > maxDist {
			return false
		}
		ent, _ := shannonEntropyAndPrintable(win)
		return ent >= minEnt && zlibCompressedRatio(win) >= minZR
	}
	if len(b) <= 1<<20 && checkWin(b) {
		return true
	}
	if len(b) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(b) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(b); off += step {
			lastOff = off
			if checkWin(b[off : off+entropyWindowBytes]) {
				return true
			}
		}
		tailOff := len(b) - entropyWindowBytes
		if tailOff > lastOff && checkWin(b[tailOff:]) {
			return true
		}
	}
	return false
}

func stripNarrowBandBytes(b []byte, bandWidth int, minFrac float64) ([]byte, bool) {
	if len(b) == 0 || bandWidth <= 0 || bandWidth >= 256 {
		return nil, false
	}
	var counts [256]int
	for _, x := range b {
		counts[x]++
	}
	winSum := 0
	for i := 0; i < bandWidth; i++ {
		winSum += counts[i]
	}
	bestLo := 0
	bestSum := winSum
	for lo := 1; lo+bandWidth <= 256; lo++ {
		winSum += counts[lo+bandWidth-1] - counts[lo-1]
		if winSum > bestSum {
			bestSum = winSum
			bestLo = lo
		}
	}
	if float64(bestSum) < float64(len(b))*minFrac {
		return nil, false
	}
	bestHi := bestLo + bandWidth - 1
	out := make([]byte, 0, len(b)-bestSum)
	for _, x := range b {
		if int(x) < bestLo || int(x) > bestHi {
			out = append(out, x)
		}
	}
	return out, true
}

func stripTopKMultiPad(b []byte, maxK int, minFrac float64) ([]byte, bool) {
	if len(b) == 0 || maxK <= 0 {
		return nil, false
	}
	var counts [256]int
	for _, x := range b {
		counts[x]++
	}
	type bvCount struct {
		val byte
		cnt int
	}
	var cands [256]bvCount
	nCands := 0
	for i, c := range counts {
		if c*100 >= len(b) {
			cands[nCands] = bvCount{val: byte(i), cnt: c}
			nCands++
		}
	}
	if nCands == 0 {
		return nil, false
	}
	sort.Slice(cands[:nCands], func(i, j int) bool {
		if cands[i].cnt != cands[j].cnt {
			return cands[i].cnt > cands[j].cnt
		}
		return cands[i].val < cands[j].val
	})
	var stripMask [256]bool
	total := 0
	lim := min(maxK, nCands)
	for i := 0; i < lim; i++ {
		if float64(total+cands[i].cnt) > float64(len(b))*0.99 {
			break
		}
		stripMask[cands[i].val] = true
		total += cands[i].cnt
	}
	if float64(total) < float64(len(b))*minFrac || len(b)-total < minEntropyBytes {
		return nil, false
	}
	out := make([]byte, 0, len(b)-total)
	for _, x := range b {
		if !stripMask[x] {
			out = append(out, x)
		}
	}
	return out, true
}

func hasEmbeddedArchiveMagic(dec []byte) bool {
	lim := min(len(dec), 32)
	for off := 1; off+10 <= lim; off++ {
		if dec[off] == 0x1f && dec[off+1] == 0x8b && dec[off+2] == 0x08 {
			if gr, err := gzip.NewReader(bytes.NewReader(dec[off:])); err == nil {
				var buf [16]byte
				n, rErr := gr.Read(buf[:])
				_ = gr.Close()
				if n > 0 && (rErr == nil || rErr == io.EOF) {
					return true
				}
			}
		}
		if dec[off] == 'P' && dec[off+1] == 'K' && dec[off+2] == 0x03 && dec[off+3] == 0x04 {
			return true
		}
	}
	return false
}

func tryDecompressZlibBounded(dec []byte, maxOut int64) ([]byte, bool) {
	if len(dec) < 8 || maxOut <= 0 || (dec[0]&0x0f) != 8 || (dec[0]>>4) > 7 {
		return nil, false
	}
	if (uint16(dec[0])*256+uint16(dec[1]))%31 != 0 || (dec[1]&0x20) != 0 {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(dec))
	if err != nil {
		return nil, false
	}
	defer func() { _ = zr.Close() }()
	inflated, err := io.ReadAll(io.LimitReader(zr, maxOut+1))
	if err != nil || len(inflated) == 0 || int64(len(inflated)) > maxOut {
		return nil, false
	}
	return inflated, true
}

func hasCredentialMatch(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var text string
	for _, rule := range concealmentCredentialRules {
		if !credentialRuleMayMatch(rule.slug, data) {
			continue
		}
		if text == "" {
			text = string(data)
		}
		if rule.re.MatchString(text) {
			if rule.slug == "api-sk-token" {
				matched := false
				for _, m := range rule.re.FindAllString(text, 8) {
					if !strings.HasPrefix(m, "sk-ssh-") && !strings.HasPrefix(m, "sk-ecdsa-") {
						matched = true
						break
					}
				}
				if matched {
					return true
				}
				continue
			}
			return true
		}
	}
	return false
}

func isActionableDigestMasquerade(dec []byte) bool {
	if len(dec) == 0 {
		return false
	}
	if !looksBinary(dec) && (hasHighPrintableAscii(dec) || hasSignificantPrintableText(dec)) {
		return true
	}
	if isValidUTF16Text(dec) {
		return true
	}
	stripped := stripControlBytesForInspection(dec)
	if len(stripped) >= 32 && ((utf8.Valid(stripped) && hasHighPrintableAscii(stripped)) || hasSignificantPrintableText(stripped)) {
		return true
	}
	if isExecutableOrArchiveMagic(dec) {
		return true
	}
	if k, _, _ := detectMagicKind(dec); k != "" {
		return true
	}
	if _, ok := tryDecompressZlibBounded(dec, maxDecodedSegmentBytes); ok {
		return true
	}
	if hasCredentialMatch(dec) || (len(stripped) > 0 && len(stripped) != len(dec) && hasCredentialMatch(stripped)) {
		return true
	}
	return false
}

func extractSpacedHexRuns(text string) []string {
	var runs []string
	n := len(text)
	i := 0
	for i < n {
		if !isHexByte(text[i]) {
			i++
			continue
		}
		if i > 0 && isHexByte(text[i-1]) {
			i++
			continue
		}
		var hexBuf strings.Builder
		tokens := 0
		pos := i
		for pos+1 < n && isHexByte(text[pos]) && isHexByte(text[pos+1]) {
			if pos+2 < n && isHexByte(text[pos+2]) {
				break
			}
			hexBuf.WriteByte(text[pos])
			hexBuf.WriteByte(text[pos+1])
			tokens++
			pos += 2
			wsStart := pos
			for pos < n && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\r' || text[pos] == '\n') {
				pos++
			}
			if pos == wsStart {
				break
			}
		}
		if tokens >= 48 {
			runs = append(runs, hexBuf.String())
		}
		if pos > i {
			i = pos
		} else {
			i++
		}
	}
	return runs
}

func extractEncodedCandidates(data []byte) []encodedCandidate {
	text := normalizeText(data)
	var candHeap encodedCandidateHeap
	seenDigests := make(map[string]struct{})
	seq := 0

	addCandidate := func(kind string, decoded []byte) bool {
		if len(decoded) < 32 || len(decoded) > maxDecodedSegmentBytes {
			return false
		}
		actionable, tier := scoreEncodedCandidate(decoded)
		if !actionable {
			return false
		}
		dig := domain.SHA256Hex(decoded)
		if _, dup := seenDigests[dig]; dup {
			return true
		}
		seenDigests[dig] = struct{}{}
		seq++
		cand := encodedCandidate{kind: kind, decoded: decoded, priorityTier: tier, seq: seq}
		if len(candHeap) < maxEncodedCandidates {
			heap.Push(&candHeap, cand)
		} else if len(candHeap) > 0 {
			top := candHeap[0]
			if cand.priorityTier > top.priorityTier || (cand.priorityTier == top.priorityTier && len(cand.decoded) > len(top.decoded)) {
				candHeap[0] = cand
				heap.Fix(&candHeap, 0)
			}
		}
		return true
	}

	tryHexRun := func(rawHex string) bool {
		if len(rawHex)%2 != 0 {
			rawHex = rawHex[:len(rawHex)-1]
		}
		if len(rawHex) < 96 || allSameByteString(rawHex) {
			return false
		}
		if decoded, err := hex.DecodeString(rawHex); err == nil {
			return addCandidate("hex", decoded)
		}
		return false
	}

	// 1. Hex blocks (>= 96 hex chars = >= 48 decoded bytes; skips 64-hex SHA-256 digests).
	for i := 0; i < len(text); {
		if !isHexByte(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && isHexByte(text[i]) {
			i++
		}
		origM := text[start:i]
		if len(origM) < 96 || allSameByteString(origM) {
			continue
		}
		if tryHexRun(origM) {
			continue
		}
		matched := false
		if rep := leadingPeriodicPrefixLen(origM); rep >= 4 && len(origM)-rep >= 96 && !allSameByteString(origM[rep:]) {
			matched = tryHexRun(origM[rep:])
			if !matched && len(origM)-rep-1 >= 96 && !allSameByteString(origM[rep+1:]) {
				matched = tryHexRun(origM[rep+1:])
			}
		}
		if !matched && len(origM)-1 >= 96 && !allSameByteString(origM[1:]) {
			_ = tryHexRun(origM[1:])
		}
	}

	// 1b. Space-separated hex byte runs (>= 48 hex pairs).
	for _, m := range extractSpacedHexRuns(text) {
		if decoded, err := hex.DecodeString(m); err == nil {
			_ = addCandidate("hex", decoded)
		}
	}

	tryB64Run := func(cand string) bool {
		if len(cand) < 64 || allSameByteString(cand) {
			return false
		}
		if decoded, ok := tryDecodeBase64(cand); ok {
			return addCandidate("b64", decoded)
		}
		matched := false
		if rep := leadingPeriodicPrefixLen(cand); rep >= 4 && len(cand)-rep >= 64 && !allSameByteString(cand[rep:]) {
			if decoded, ok := tryDecodeBase64(cand[rep:]); ok {
				matched = addCandidate("b64", decoded)
			}
			for off := 1; !matched && off <= 3 && len(cand)-rep-off >= 64; off++ {
				sub := cand[rep+off:]
				if allSameByteString(sub) {
					continue
				}
				if decoded, ok := tryDecodeBase64(sub); ok {
					matched = addCandidate("b64", decoded)
				}
			}
		}
		if !matched {
			for off := 1; off <= 3 && len(cand)-off >= 64; off++ {
				sub := cand[off:]
				if allSameByteString(sub) {
					continue
				}
				if decoded, ok := tryDecodeBase64(sub); ok {
					matched = addCandidate("b64", decoded)
					if matched {
						break
					}
				}
			}
		}
		if !matched && len(cand)%4 == 1 && len(cand)-1 >= 64 {
			if decoded, ok := tryDecodeBase64(cand[:len(cand)-1]); ok {
				matched = addCandidate("b64", decoded)
			}
		}
		return matched
	}

	// 2. Single-line / inline base64 runs (>= 64 chars).
	for i := 0; i < len(text); {
		if !isBase64Char(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && isBase64Char(text[i]) {
			i++
		}
		m := text[start:i]
		if len(m) < 64 || allSameByteString(m) {
			continue
		}
		if !tryB64Run(m) {
			if eq := findLastInteriorEqWithMinTail(m, 64); eq >= 0 {
				_ = tryB64Run(m[eq+1:])
			}
		}
	}

	// 3. Multi-line wrapped base64 and hex blocks (consecutive lines of 4..128 encoded chars, raw or comment-wrapped, plus 1..3 char final tail).
	lines := strings.Split(text, "\n")
	collectWrapped := func(stripComments bool) {
		var b64Block strings.Builder
		b64Lines := 0
		b64MinLine := math.MaxInt
		var hexBlock strings.Builder
		hexLines := 0
		hexMinLine := math.MaxInt
		flushB64 := func() {
			minNeeded := 3
			if b64MinLine >= 32 {
				minNeeded = 2
			} else if b64MinLine >= 8 && b64MinLine < 16 {
				minNeeded = 4
			} else if b64MinLine < 8 {
				minNeeded = 6
			}
			if b64Lines >= minNeeded && b64Block.Len() >= 64 {
				if decoded, ok := tryDecodeBase64(b64Block.String()); ok {
					_ = addCandidate("b64", decoded)
				}
			}
			b64Block.Reset()
			b64Lines = 0
			b64MinLine = math.MaxInt
		}
		flushHex := func() {
			minNeeded := 3
			if hexMinLine >= 32 {
				minNeeded = 2
			} else if hexMinLine >= 8 && hexMinLine < 16 {
				minNeeded = 4
			} else if hexMinLine < 8 {
				minNeeded = 6
			}
			if hexLines >= minNeeded && hexBlock.Len() >= 96 {
				hexStr := hexBlock.String()
				if len(hexStr)%2 != 0 {
					hexStr = hexStr[:len(hexStr)-1]
				}
				if len(hexStr) >= 96 {
					if decoded, err := hex.DecodeString(hexStr); err == nil {
						_ = addCandidate("hex", decoded)
					}
				}
			}
			hexBlock.Reset()
			hexLines = 0
			hexMinLine = math.MaxInt
		}
		for _, line := range lines {
			s := strings.TrimSpace(line)
			if stripComments {
				cleaned, skipWrapper := stripWrappedCommentLine(s)
				if skipWrapper {
					continue
				}
				s = cleaned
			}
			b64Line := s
			strippedAssign := false
			if val, ok := stripKeyEqB64Prefix(s); ok {
				if b64Lines > 0 {
					flushB64()
				}
				b64Line = val
				strippedAssign = true
			}
			if len(b64Line) >= 4 && len(b64Line) <= 128 && isBase64Line(b64Line) &&
				(b64Lines > 0 || !strings.HasSuffix(b64Line, "=")) {
				b64Block.WriteString(b64Line)
				b64Lines++
				if len(b64Line) < b64MinLine {
					b64MinLine = len(b64Line)
				}
			} else if !strippedAssign && b64Lines >= 2 && b64Block.Len() >= 32 && len(s) >= 1 && len(s) <= 3 && isBase64Line(s) {
				b64Block.WriteString(s)
				b64Lines++
				flushB64()
			} else {
				flushB64()
			}
			if len(s) >= 4 && len(s) <= 128 && isHexString(s) {
				hexBlock.WriteString(s)
				hexLines++
				if len(s) < hexMinLine {
					hexMinLine = len(s)
				}
			} else if hexLines >= 2 && hexBlock.Len() >= 32 && len(s) >= 1 && len(s) <= 3 && isHexString(s) {
				hexBlock.WriteString(s)
				hexLines++
				flushHex()
			} else {
				flushHex()
			}
		}
		flushB64()
		flushHex()
	}
	collectWrapped(false)
	collectWrapped(true)

	// 4. Quoted string concatenations (e.g. "..." + \n "..." or adjacent Python/C literals).
	for _, joined := range extractQuotedConcatenatedStrings(text) {
		if len(joined) >= 96 && isHexString(joined) {
			if !tryHexRun(joined) {
				if rep := leadingPeriodicPrefixLen(joined); rep >= 4 && len(joined)-rep >= 96 {
					_ = tryHexRun(joined[rep:])
				}
			}
		}
		if decoded, ok := tryDecodeBase64(joined); ok {
			_ = addCandidate("b64", decoded)
		} else {
			matched := false
			if rep := leadingPeriodicPrefixLen(joined); rep >= 4 && len(joined)-rep >= 64 {
				if decoded, ok := tryDecodeBase64(joined[rep:]); ok {
					matched = addCandidate("b64", decoded)
				}
			}
			if !matched && len(joined)%4 == 1 && len(joined)-1 >= 64 {
				if decoded, ok := tryDecodeBase64(joined[:len(joined)-1]); ok {
					matched = addCandidate("b64", decoded)
				}
			}
			if !matched {
				if eq := findLastInteriorEqWithMinTail(joined, 64); eq >= 0 {
					sub := joined[eq+1:]
					if decoded, ok := tryDecodeBase64(sub); ok {
						_ = addCandidate("b64", decoded)
					} else if len(sub)%4 == 1 && len(sub)-1 >= 64 {
						if decoded, ok := tryDecodeBase64(sub[:len(sub)-1]); ok {
							_ = addCandidate("b64", decoded)
						}
					}
				}
			}
		}
		if strings.Contains(joined, "<~") && strings.Contains(joined, "~>") {
			for pos := 0; pos < len(joined); {
				rel := strings.Index(joined[pos:], "<~")
				if rel < 0 {
					break
				}
				bodyStart := pos + rel + 2
				endRel := strings.Index(joined[bodyStart:], "~>")
				if endRel < 0 {
					break
				}
				bodyEnd := bodyStart + endRel
				decodedOK := false
				if bodyEnd-bodyStart >= 64 && bodyEnd-bodyStart <= maxDecodedSegmentBytes*2 {
					dec := ascii85.NewDecoder(strings.NewReader(joined[bodyStart:bodyEnd]))
					decoded, err := io.ReadAll(io.LimitReader(dec, maxDecodedSegmentBytes+1))
					if err == nil && len(decoded) >= 32 && len(decoded) <= maxDecodedSegmentBytes {
						_ = addCandidate("a85", decoded)
						decodedOK = true
					}
				}
				if !decodedOK {
					if lastRel := strings.LastIndex(joined[bodyStart:bodyEnd], "<~"); lastRel >= 0 {
						pos = bodyStart + lastRel
						continue
					}
				}
				pos = bodyEnd + 2
			}
		}
	}

	// 5. ASCII85 <~...~> payloads (>= 64 chars, bounded).
	for pos := 0; pos < len(text); {
		rel := strings.Index(text[pos:], "<~")
		if rel < 0 {
			break
		}
		bodyStart := pos + rel + 2
		endRel := strings.Index(text[bodyStart:], "~>")
		if endRel < 0 {
			break
		}
		bodyEnd := bodyStart + endRel
		decodedOK := false
		if bodyEnd-bodyStart >= 64 && bodyEnd-bodyStart <= maxDecodedSegmentBytes*2 {
			dec := ascii85.NewDecoder(strings.NewReader(text[bodyStart:bodyEnd]))
			decoded, err := io.ReadAll(io.LimitReader(dec, maxDecodedSegmentBytes+1))
			if err == nil && len(decoded) >= 32 && len(decoded) <= maxDecodedSegmentBytes {
				_ = addCandidate("a85", decoded)
				decodedOK = true
			}
		}
		if !decodedOK {
			if lastRel := strings.LastIndex(text[bodyStart:bodyEnd], "<~"); lastRel >= 0 {
				pos = bodyStart + lastRel
				continue
			}
		}
		pos = bodyEnd + 2
	}

	// 5b. Comment-wrapped ASCII85 <~...~> payloads (e.g. // | <~...~>).
	if strings.Contains(text, "<~") && strings.Contains(text, "~>") {
		var csBuf strings.Builder
		strippedAny := false
		for _, line := range lines {
			s := strings.TrimSpace(line)
			if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") ||
				strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "*") ||
				strings.HasPrefix(s, "--") || strings.HasPrefix(s, "|") ||
				strings.HasPrefix(s, "<!--") || strings.HasSuffix(s, "-->") {
				strippedAny = true
			}
			cleaned, skipWrapper := stripWrappedCommentLine(s)
			if skipWrapper || cleaned == "" {
				continue
			}
			if strippedAny {
				if csBuf.Len() == 0 {
					csBuf.Grow(len(text))
				}
				csBuf.WriteString(cleaned)
				csBuf.WriteByte('\n')
			}
		}
		if strippedAny && csBuf.Len() > 0 {
			commentStripped := csBuf.String()
			for pos := 0; pos < len(commentStripped); {
				rel := strings.Index(commentStripped[pos:], "<~")
				if rel < 0 {
					break
				}
				bodyStart := pos + rel + 2
				endRel := strings.Index(commentStripped[bodyStart:], "~>")
				if endRel < 0 {
					break
				}
				bodyEnd := bodyStart + endRel
				decodedOK := false
				if bodyEnd-bodyStart >= 64 && bodyEnd-bodyStart <= maxDecodedSegmentBytes*2 {
					dec := ascii85.NewDecoder(strings.NewReader(commentStripped[bodyStart:bodyEnd]))
					decoded, err := io.ReadAll(io.LimitReader(dec, maxDecodedSegmentBytes+1))
					if err == nil && len(decoded) >= 32 && len(decoded) <= maxDecodedSegmentBytes {
						_ = addCandidate("a85", decoded)
						decodedOK = true
					}
				}
				if !decodedOK {
					if lastRel := strings.LastIndex(commentStripped[bodyStart:bodyEnd], "<~"); lastRel >= 0 {
						pos = bodyStart + lastRel
						continue
					}
				}
				pos = bodyEnd + 2
			}
		}
	}

	out := []encodedCandidate(candHeap)
	sort.Slice(out, func(i, j int) bool {
		if out[i].priorityTier != out[j].priorityTier {
			return out[i].priorityTier > out[j].priorityTier
		}
		if len(out[i].decoded) != len(out[j].decoded) {
			return len(out[i].decoded) > len(out[j].decoded)
		}
		return out[i].seq < out[j].seq
	})
	return out
}

func findLastInteriorEqWithMinTail(s string, minTail int) int {
	for k := len(s) - 2; k >= 0; k-- {
		if s[k] == '=' && s[k+1] != '=' && len(s)-(k+1) >= minTail {
			return k
		}
	}
	return -1
}

func stripKeyEqB64Prefix(s string) (string, bool) {
	eq := findLastInteriorEqWithMinTail(s, 4)
	if eq <= 0 {
		return s, false
	}
	prefix := strings.TrimSpace(s[:eq])
	if len(prefix) == 0 {
		return s, false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '-' || c == ':' || c == '/' || c == '?' || c == '&' || c == '+' || c == '%') {
			return s, false
		}
	}
	val := strings.TrimSpace(s[eq+1:])
	if len(val) < 4 || len(val) > 128 || !isBase64Line(val) {
		return s, false
	}
	nonEq := 0
	for i := 0; i < len(val); i++ {
		if val[i] != '=' {
			nonEq++
		}
	}
	if nonEq < 4 {
		return s, false
	}
	return val, true
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

func isBase64Line(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isBase64Char(s[i]) {
			return false
		}
	}
	return true
}

func isUnpaddedBase64String(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' || !isBase64Char(c) {
			return false
		}
	}
	return true
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

func scoreEncodedCandidate(dec []byte) (actionable bool, priorityTier int) {
	if len(dec) == 0 {
		return false, 0
	}
	stripped := stripControlBytesForInspection(dec)
	if hasCredentialMatch(dec) || (len(stripped) > 0 && len(stripped) != len(dec) && hasCredentialMatch(stripped)) {
		return true, 2
	}
	if isExecutableOrArchiveMagic(dec) {
		return true, 2
	}
	if k, _, _ := detectMagicKind(dec); k != "" {
		return true, 2
	}
	if _, ok := tryDecompressZlibBounded(dec, maxDecodedSegmentBytes); ok {
		return true, 2
	}
	if len(dec) >= minEntropyBytes {
		if _, flagged := checkHighEntropy(dec); flagged {
			return true, 2
		}
	}
	if inferLanguageFromContent(dec) != "" || (len(stripped) > 0 && len(stripped) != len(dec) && inferLanguageFromContent(stripped) != "") {
		return true, 1
	}
	if !looksBinary(dec) && (hasHighPrintableAscii(dec) || utf8.Valid(dec)) {
		return true, 0
	}
	if isValidUTF16Text(dec) {
		return true, 0
	}
	if len(stripped) >= 32 && ((utf8.Valid(stripped) && hasHighPrintableAscii(stripped)) || hasSignificantPrintableText(stripped)) {
		return true, 0
	}
	return false, 0
}

func isActionableDecoded(dec []byte) bool {
	ok, _ := scoreEncodedCandidate(dec)
	return ok
}

// skipJSInterpolation skips bounded template literal interpolations such as ${”}, ${a}, ${obj.empty}, or ${cond ? ” : ""}.
func skipJSInterpolation(text string, dollarIdx int, braceCache, blockCmtCache, lineCmtCache *commentTermCache) (endIdx int, ok bool) {
	n := len(text)
	if dollarIdx+1 >= n || text[dollarIdx] != '$' || text[dollarIdx+1] != '{' {
		return 0, false
	}
	p := dollarIdx + 2
	limit := min(n, p+4096)
	if braceCache != nil {
		nextBrace, hasBrace := braceCache.findNext(p)
		if !hasBrace || nextBrace >= limit {
			return 0, false
		}
	}
	depth := 1
	for p < limit {
		c := text[p]
		switch c {
		case '{':
			depth++
			p++
		case '}':
			depth--
			p++
			if depth == 0 {
				return p, true
			}
		case '\'', '"', '`':
			q := c
			p++
			for p < limit {
				if text[p] == '\\' && p+1 < limit {
					p += 2
					continue
				}
				if text[p] == q {
					p++
					break
				}
				p++
			}
		case '/':
			if p+1 < limit && text[p+1] == '*' {
				if blockCmtCache != nil {
					absEnd, found := blockCmtCache.findNext(p + 2)
					if !found || absEnd+2 > limit {
						return 0, false
					}
					p = absEnd + 2
				} else {
					endCmt := strings.Index(text[p+2:limit], "*/")
					if endCmt < 0 {
						return 0, false
					}
					p += 2 + endCmt + 2
				}
			} else if p+1 < limit && text[p+1] == '/' {
				if lineCmtCache != nil {
					absNL, found := lineCmtCache.findNext(p + 2)
					if !found || absNL+1 > limit {
						return 0, false
					}
					p = absNL + 1
				} else {
					nl := strings.IndexByte(text[p+2:limit], '\n')
					if nl < 0 {
						return 0, false
					}
					p += 2 + nl + 1
				}
			} else {
				p++
			}
		default:
			p++
		}
	}
	return 0, false
}

func skipBalancedBraces(text string, braceIdx int, braceCache *commentTermCache) (endIdx int, ok bool) {
	n := len(text)
	if braceIdx >= n || text[braceIdx] != '{' {
		return 0, false
	}
	p := braceIdx + 1
	limit := min(n, p+4096)
	if braceCache != nil {
		nextBrace, hasBrace := braceCache.findNext(p)
		if !hasBrace || nextBrace >= limit {
			return 0, false
		}
	}
	depth := 1
	for p < limit {
		c := text[p]
		switch c {
		case '{':
			depth++
			p++
		case '}':
			depth--
			p++
			if depth == 0 {
				return p, true
			}
		case '\'', '"':
			q := c
			p++
			for p < limit {
				if text[p] == '\\' && p+1 < limit {
					p += 2
					continue
				}
				if text[p] == q {
					p++
					break
				}
				p++
			}
		default:
			p++
		}
	}
	return 0, false
}

func isIdentLikeByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

func hasPythonFStringPrefix(text string, quoteIdx int) bool {
	if quoteIdx >= 1 && (text[quoteIdx-1] == 'f' || text[quoteIdx-1] == 'F') {
		if quoteIdx == 1 || !isIdentLikeByte(text[quoteIdx-2]) {
			return true
		}
	}
	if quoteIdx >= 2 {
		c0 := text[quoteIdx-2]
		c1 := text[quoteIdx-1]
		isFR := (c0 == 'f' || c0 == 'F') && (c1 == 'r' || c1 == 'R')
		isRF := (c0 == 'r' || c0 == 'R') && (c1 == 'f' || c1 == 'F')
		if (isFR || isRF) && (quoteIdx == 2 || !isIdentLikeByte(text[quoteIdx-3])) {
			return true
		}
	}
	return false
}

func pythonStringPrefixLen(text string, pos int) int {
	n := len(text)
	if pos+1 < n && (text[pos+1] == '"' || text[pos+1] == '\'') {
		c := text[pos]
		if c == 'f' || c == 'F' || c == 'r' || c == 'R' || c == 'b' || c == 'B' || c == 'u' || c == 'U' {
			return 1
		}
	}
	if pos+2 < n && (text[pos+2] == '"' || text[pos+2] == '\'') {
		c0, c1 := text[pos], text[pos+1]
		l0, l1 := c0|0x20, c1|0x20
		if (l0 == 'f' && l1 == 'r') || (l0 == 'r' && l1 == 'f') || (l0 == 'b' && l1 == 'r') || (l0 == 'r' && l1 == 'b') {
			return 2
		}
	}
	return 0
}

func hasDigestIdentifierContext(text string, start, end int) bool {
	win := strings.ToLower(text[max(0, start-512):min(len(text), end+512)])
	for _, kw := range []string{
		"sha256", "sha512", "sha384", "sha1", "md5", "blake",
		"digest", "checksum", "hash", "integrity", "sri", "merkle", "fingerprint",
	} {
		if strings.Contains(win, kw) {
			return true
		}
	}
	return false
}

func hasJoinLookbehindOrVarJoin(text string, arrayQuoteStart, arrayEndPos int) bool {
	// Walk back across opening [ / { / whitespace / Go slice type prefix (e.g. []string{) up to 512 bytes.
	lbStart := arrayQuoteStart
	lbMin := max(0, arrayQuoteStart-512)
	var assignPos int = -1
	for p := lbStart - 1; p >= lbMin; p-- {
		if text[p] == '=' && assignPos < 0 && p >= arrayQuoteStart-64 {
			assignPos = p
		}
		if text[p] == '[' || text[p] == '{' {
			// Check immediately preceding context before [ or {.
			ctxStart := max(0, p-128)
			before := text[ctxStart:p]
			if strings.Contains(before, ".join(") || strings.Contains(before, "strings.Join(") ||
				strings.Contains(before, ".join ") || strings.Contains(before, "strings.Join ") ||
				strings.Contains(before, "hex.Decode") || strings.Contains(before, "fromhex(") ||
				strings.Contains(before, "Buffer.from(") || strings.Contains(before, "atob(") ||
				strings.Contains(before, "b64decode(") || strings.Contains(before, "DecodeString(") {
				return true
			}
			// Also check if `const c = [...]` or `c := []string{...}` assigns to a variable joined nearby.
			assignScan := before
			if eqIdx := strings.LastIndexByte(assignScan, '='); eqIdx >= 0 {
				assignPos = ctxStart + eqIdx
			}
			break
		}
		if text[p] == ';' || text[p] == '\n' && p < arrayQuoteStart-4 {
			// Still allow multi-line `[\n  "..."`
			continue
		}
	}
	lookahead := text[arrayEndPos:min(len(text), arrayEndPos+512)]
	for _, decCall := range []string{
		"WriteString(", "+=", ".concat(", ".reduce(",
		"hex.Decode", "fromhex(", "Buffer.from(", "atob(",
		"b64decode(", "urlsafe_b64decode(", "DecodeString(",
	} {
		if strings.Contains(lookahead, decCall) {
			return true
		}
	}
	if assignPos >= 0 {
		lhs := strings.TrimSpace(text[max(0, assignPos-48):assignPos])
		lhs = strings.TrimSuffix(lhs, ":")
		lhs = strings.TrimSpace(lhs)
		fields := strings.Fields(lhs)
		if len(fields) > 0 {
			varName := fields[len(fields)-1]
			if brIdx := strings.IndexByte(varName, '['); brIdx > 0 {
				varName = varName[:brIdx]
			}
			if len(varName) > 0 && isIdentLike(varName) {
				if strings.Contains(lookahead, varName+".join(") ||
					strings.Contains(lookahead, varName+".reduce(") ||
					strings.Contains(lookahead, varName+".concat(") ||
					strings.Contains(lookahead, "strings.Join("+varName) ||
					strings.Contains(lookahead, "strings.Join( "+varName) ||
					strings.Contains(lookahead, `".join(`+varName) ||
					strings.Contains(lookahead, `'.join(`+varName) ||
					strings.Contains(lookahead, `".join( `+varName) ||
					strings.Contains(lookahead, `'.join( `+varName) {
					return true
				}
			}
		}
	}
	return false
}

func isIdentLike(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$') {
			return false
		}
	}
	return len(s) > 0
}

func decodeDigestArrayPayload(joined string, isHex bool) ([]byte, bool) {
	if isHex {
		if len(joined)%2 != 0 {
			return nil, false
		}
		dec, err := hex.DecodeString(joined)
		if err != nil {
			return nil, false
		}
		return dec, true
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.StdEncoding} {
		if dec, err := enc.DecodeString(joined); err == nil && len(dec) > 0 {
			return dec, true
		}
	}
	return nil, false
}

func decodeUniformB64Segments(segs []string) ([]byte, bool) {
	if len(segs) == 0 {
		return nil, false
	}
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.StdEncoding}
	var out bytes.Buffer
	for _, seg := range segs {
		var segDec []byte
		ok := false
		for _, enc := range encodings {
			if dec, err := enc.DecodeString(seg); err == nil && len(dec) > 0 {
				segDec = dec
				ok = true
				break
			}
		}
		if !ok {
			return nil, false
		}
		out.Write(segDec)
	}
	return out.Bytes(), out.Len() > 0
}

type commentHint struct {
	from int
	at   int
}

type commentTermCache struct {
	text     string
	term     string
	hints    []commentHint
	head     int
	noMoreAt int
}

func newCommentTermCache(text, term string) *commentTermCache {
	return &commentTermCache{
		text:     text,
		term:     term,
		noMoreAt: len(text),
	}
}

func (c *commentTermCache) advanceOuter(outerI int) {
	for c.head < len(c.hints) && c.hints[c.head].at < outerI {
		c.head++
	}
}

func (c *commentTermCache) findNext(searchStart int) (int, bool) {
	if searchStart >= c.noMoreAt {
		return 0, false
	}
	active := c.hints[c.head:]
	lo, hi := 0, len(active)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if active[mid].at < searchStart {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(active) {
		h := &c.hints[c.head+lo]
		if searchStart >= h.from {
			return h.at, true
		}
		limit := min(len(c.text), h.from+len(c.term)-1)
		rel := strings.Index(c.text[searchStart:limit], c.term)
		if rel < 0 {
			h.from = searchStart
			return h.at, true
		}
		absAt := searchStart + rel
		pos := c.head + lo
		c.hints = append(c.hints, commentHint{})
		copy(c.hints[pos+1:], c.hints[pos:])
		c.hints[pos] = commentHint{from: searchStart, at: absAt}
		return absAt, true
	}

	limit := min(len(c.text), c.noMoreAt+len(c.term)-1)
	rel := strings.Index(c.text[searchStart:limit], c.term)
	if rel < 0 {
		if searchStart < c.noMoreAt {
			c.noMoreAt = searchStart
		}
		return 0, false
	}
	absAt := searchStart + rel
	c.hints = append(c.hints, commentHint{from: searchStart, at: absAt})
	return absAt, true
}

func isASCII85BodyChar(c byte) bool {
	return (c >= '!' && c <= 'u') || c == 'z' || c == 'y' || c == '~'
}

func skipWSAndCommentsBounded(text string, k int, blockCmtCache, lineCmtCache, htmlCmtCache *commentTermCache) (newK int, sawNL bool) {
	n := len(text)
	for steps := 0; k < n && steps < 16; steps++ {
		c := text[k]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			for k < n && (text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n') {
				if text[k] == '\n' {
					sawNL = true
				}
				k++
			}
			continue
		}
		if c == '/' && k+1 < n && text[k+1] == '*' {
			searchStart := k + 2
			if blockCmtCache != nil {
				absEnd, ok := blockCmtCache.findNext(searchStart)
				if !ok || absEnd+2 > min(n, searchStart+maxInlineCommentSkipBytes) {
					break
				}
				k = absEnd + 2
				continue
			}
			endCmt := strings.Index(text[searchStart:min(n, searchStart+4096)], "*/")
			if endCmt < 0 {
				break
			}
			k = searchStart + endCmt + 2
			continue
		}
		if c == '/' && k+1 < n && text[k+1] == '/' {
			searchStart := k + 2
			if lineCmtCache != nil {
				absNL, ok := lineCmtCache.findNext(searchStart)
				if !ok || absNL+1 > min(n, searchStart+maxInlineCommentSkipBytes) {
					break
				}
				sawNL = true
				k = absNL + 1
				continue
			}
			nl := strings.IndexByte(text[searchStart:min(n, searchStart+4096)], '\n')
			if nl < 0 {
				break
			}
			sawNL = true
			k = searchStart + nl + 1
			continue
		}
		if c == '<' && k+3 < n && text[k+1] == '!' && text[k+2] == '-' && text[k+3] == '-' {
			searchStart := k + 4
			if htmlCmtCache != nil {
				absEnd, ok := htmlCmtCache.findNext(searchStart)
				if !ok || absEnd-searchStart > maxInlineCommentSkipBytes {
					break
				}
				k = absEnd + 3
				continue
			}
			endCmt := strings.Index(text[searchStart:min(n, searchStart+4096)], "-->")
			if endCmt < 0 {
				break
			}
			k = searchStart + endCmt + 3
			continue
		}
		break
	}
	return k, sawNL
}

func skipExtendedSep(text string, next int, sawNewline bool, blockCmtCache, lineCmtCache, htmlCmtCache *commentTermCache) (newNext int, ok bool, isCommaLike bool) {
	n := len(text)
	if next >= n {
		return 0, false, false
	}
	// Case A: Object-array separator: [ \t\r\n,{}/*...*/]* (optional key: unquoted_scalar, )* (ident | 'ident' | "ident") : quote
	if text[next] == '{' || text[next] == '}' {
		k := next
		sawBrace := false
		sawComma := false
		for steps := 0; k < n && steps < 16; steps++ {
			c := text[k]
			if c == '{' || c == '}' {
				sawBrace = true
				k++
			} else if c == ',' {
				sawComma = true
				k++
			} else if c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
				(c == '/' && k+1 < n && (text[k+1] == '*' || text[k+1] == '/')) ||
				(c == '<' && k+3 < n && text[k+1] == '!' && text[k+2] == '-' && text[k+3] == '-') {
				nk, _ := skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if nk == k {
					break
				}
				k = nk
			} else {
				break
			}
		}
		if sawBrace && k < n {
			for field := 0; field < 4 && k < n; field++ {
				lim := min(n, k+128)
				keyOK := false
				if text[k] == '"' || text[k] == '\'' {
					kq := text[k]
					k++
					idStart := k
					for k < lim && k-idStart < 24 && isIdentLikeByte(text[k]) {
						k++
					}
					if k > idStart && k < lim && text[k] == kq {
						k++
						keyOK = true
					}
				} else {
					idStart := k
					for k < lim && k-idStart < 24 && isIdentLikeByte(text[k]) {
						k++
					}
					if k > idStart {
						keyOK = true
					}
				}
				if !keyOK {
					break
				}
				k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if k >= n || text[k] != ':' {
					break
				}
				k++
				k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if k < n && (text[k] == '"' || text[k] == '\'' || text[k] == '`') {
					return k, true, sawComma || sawBrace
				}
				// Allow skipping a short unquoted scalar field value (e.g. id: 0, flag: true, s: "...")
				valStart := k
				valLim := min(n, k+32)
				for k < valLim {
					vc := text[k]
					if (vc >= '0' && vc <= '9') || (vc >= 'a' && vc <= 'z') || (vc >= 'A' && vc <= 'Z') || vc == '_' || vc == '.' || vc == '-' {
						k++
					} else {
						break
					}
				}
				if k == valStart {
					break
				}
				k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if k < n && text[k] == ',' {
					sawComma = true
					k++
					k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
					continue
				}
				break
			}
		}
	}
	// Case B: Statement-separated assignment / append: (';' | '\n') WS/cmts ident ('[' idx ']' '=' | '+=' | '.push(' | '.append(' | '.WriteString(') quote
	if sawNewline || text[next] == ';' {
		k := next
		for k < n && k-next < 16 && (text[k] == ';' || text[k] == ')') {
			k++
		}
		k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
		lim := min(n, k+128)
		idStart := k
		for k < lim && k-idStart < 48 && (isIdentLikeByte(text[k]) || text[k] == '.') {
			k++
		}
		if k > idStart {
			ident := text[idStart:k]
			k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
			lim = min(n, k+128)
			if k+1 < lim && text[k] == '+' && text[k+1] == '=' {
				k += 2
				k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if k < n && (text[k] == '"' || text[k] == '\'' || text[k] == '`') {
					return k, true, false
				}
			} else if k < lim && text[k] == '[' && !strings.ContainsRune(ident, '.') {
				k++
				idxStart := k
				for k < lim && k-idxStart < 24 && text[k] != ']' && text[k] != '\n' && text[k] != '\r' {
					k++
				}
				if k > idxStart && k < lim && text[k] == ']' {
					k++
					k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
					if k < n && text[k] == '=' && !(k+1 < n && text[k+1] == '=') {
						k++
						k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
						if k < n && (text[k] == '"' || text[k] == '\'' || text[k] == '`') {
							return k, true, true
						}
					}
				}
			} else if k < lim && text[k] == '(' &&
				(strings.HasSuffix(ident, ".push") || strings.HasSuffix(ident, ".append") || strings.HasSuffix(ident, ".WriteString")) {
				k++
				k, _ = skipWSAndCommentsBounded(text, k, blockCmtCache, lineCmtCache, htmlCmtCache)
				if k < n && (text[k] == '"' || text[k] == '\'' || text[k] == '`') {
					return k, true, true
				}
			}
		}
	}
	return 0, false, false
}

func extractQuotedConcatenatedStrings(text string) []string {
	var results []string
	n := len(text)
	blockCmtCache := newCommentTermCache(text, "*/")
	lineCmtCache := newCommentTermCache(text, "\n")
	htmlCmtCache := newCommentTermCache(text, "-->")
	braceCache := newCommentTermCache(text, "}")
	i := 0
	for i < n {
		if text[i] != '"' && text[i] != '\'' && text[i] != '`' {
			i++
			continue
		}
		blockCmtCache.advanceOuter(i)
		lineCmtCache.advanceOuter(i)
		htmlCmtCache.advanceOuter(i)
		braceCache.advanceOuter(i)

		var joined strings.Builder
		var segs []string
		segments := 0
		templateSplits := 0
		firstSegLen := 0
		sawCommaSeparator := false
		sawPlusOrDot := false
		allUniformHexDigest := true
		allUniformB64Digest := true
		a85Mode := false
		pendingOpenLT := false
		pos := i
		for pos < n {
			quote := text[pos]
			if quote != '"' && quote != '\'' && quote != '`' {
				break
			}
			isFString := (quote == '"' || quote == '\'') && hasPythonFStringPrefix(text, pos)
			delimLen := 1
			if (quote == '"' || quote == '\'') && pos+2 < n && text[pos+1] == quote && text[pos+2] == quote {
				delimLen = 3
			}
			start := pos + delimLen
			if segments == 0 && start < n && text[start] == '<' {
				if start+1 < n && text[start+1] == '~' {
					a85Mode = true
				}
			} else if pendingOpenLT && start < n && text[start] == '~' {
				a85Mode = true
			}
			isSingleOpenLTSeg := segments == 0 && start < n && text[start] == '<' &&
				((delimLen == 1 && start+1 < n && text[start+1] == quote) ||
					(delimLen == 3 && start+3 < n && text[start+1] == quote && text[start+2] == quote && text[start+3] == quote))
			pendingOpenLT = false
			j := start
			validSeg := true
			plain := true
			var segBuf strings.Builder
			flushPlain := func(upto int) {
				if plain {
					if upto > start {
						segBuf.WriteString(text[start:upto])
					}
					plain = false
				}
			}
			for j < n {
				if delimLen == 3 {
					if j+2 < n && text[j] == quote && text[j+1] == quote && text[j+2] == quote {
						break
					}
					if text[j] == '\r' || text[j] == '\n' {
						flushPlain(j)
						j++
						continue
					}
				} else {
					if text[j] == quote {
						break
					}
					if quote == '`' {
						if text[j] == '\r' || text[j] == '\n' {
							flushPlain(j)
							j++
							continue
						}
						if text[j] == '$' && j+1 < n && text[j+1] == '{' {
							if endInterp, ok := skipJSInterpolation(text, j, braceCache, blockCmtCache, lineCmtCache); ok {
								flushPlain(j)
								templateSplits++
								j = endInterp
								continue
							}
							validSeg = false
							break
						}
					}
					if text[j] == '\n' {
						validSeg = false
						break
					}
				}
				if isFString && text[j] == '{' {
					if endBrace, ok := skipBalancedBraces(text, j, braceCache); ok {
						flushPlain(j)
						templateSplits++
						j = endBrace
						continue
					}
					validSeg = false
					break
				}
				if text[j] == '\\' && j+1 < n {
					nextCh := text[j+1]
					if nextCh == 'n' || nextCh == 'r' || nextCh == 't' || nextCh == '\n' {
						flushPlain(j)
						templateSplits++
						j += 2
						continue
					}
					if nextCh == '\r' && j+2 < n && text[j+2] == '\n' {
						flushPlain(j)
						templateSplits++
						j += 3
						continue
					}
					if a85Mode && (nextCh == '"' || nextCh == '\'' || nextCh == '\\') {
						flushPlain(j)
						segBuf.WriteByte(nextCh)
						j += 2
						continue
					}
					validSeg = false
					break
				}
				if text[j] == '\\' || (!a85Mode && !isBase64Char(text[j]) && !(isSingleOpenLTSeg && j == start && text[j] == '<')) || (a85Mode && !isASCII85BodyChar(text[j])) {
					validSeg = false
					break
				}
				if !plain {
					segBuf.WriteByte(text[j])
				}
				j++
			}
			var segStr string
			if plain {
				segStr = text[start:j]
			} else {
				segStr = segBuf.String()
			}
			minSeg := 1
			closed := (delimLen == 3 && j+2 < n && text[j] == quote && text[j+1] == quote && text[j+2] == quote) ||
				(delimLen == 1 && j < n && text[j] == quote)
			if !validSeg || !closed || (len(segStr) < minSeg && segments == 0) {
				break
			}
			if a85Mode {
				allUniformHexDigest = false
				allUniformB64Digest = false
			}
			if len(segStr) == 0 {
				templateSplits++
				allUniformHexDigest = false
				allUniformB64Digest = false
			} else {
				if segments == 0 {
					firstSegLen = len(segStr)
					if segStr == "<" {
						pendingOpenLT = true
					}
				}
				if len(segStr) != firstSegLen ||
					(firstSegLen != 32 && firstSegLen != 40 && firstSegLen != 64 && firstSegLen != 128) ||
					!isHexString(segStr) {
					allUniformHexDigest = false
				}
				if len(segStr) != firstSegLen ||
					(firstSegLen != 22 && firstSegLen != 27 && firstSegLen != 43 && firstSegLen != 86) ||
					!isUnpaddedBase64String(segStr) {
					allUniformB64Digest = false
				}
				if allUniformB64Digest && len(segs) < 1024 {
					segs = append(segs, segStr)
				}
				joined.WriteString(segStr)
				segments++
			}
			pos = j + delimLen

			// Advance across concatenation separators: whitespace, +, ., \, commas, parentheses, and bounded inline comments.
			next := pos
			segHasComma := false
			segHasPlusOrDot := false
			sawNewline := false
			for next < n {
				c := text[next]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '+' || c == '.' || c == '\\' || c == ',' || c == '(' || c == ')' {
					if c == '\n' {
						sawNewline = true
					}
					if c == ',' {
						segHasComma = true
					}
					if c == '+' || c == '.' || c == '\\' {
						segHasPlusOrDot = true
					}
					next++
					continue
				}
				if pLen := pythonStringPrefixLen(text, next); pLen > 0 {
					next += pLen
					break
				}
				if c == '/' && next+1 < n && text[next+1] == '*' {
					searchStart := next + 2
					absEnd, ok := blockCmtCache.findNext(searchStart)
					if !ok || absEnd-searchStart > maxInlineCommentSkipBytes {
						break
					}
					next = absEnd + 2
					continue
				}
				if c == '/' && next+1 < n && text[next+1] == '/' {
					searchStart := next + 2
					absNL, ok := lineCmtCache.findNext(searchStart)
					if !ok || absNL-searchStart > maxInlineCommentSkipBytes {
						break
					}
					sawNewline = true
					next = absNL + 1
					continue
				}
				if c == '#' {
					searchStart := next + 1
					absNL, ok := lineCmtCache.findNext(searchStart)
					if !ok || absNL-searchStart > maxInlineCommentSkipBytes {
						break
					}
					sawNewline = true
					next = absNL + 1
					continue
				}
				if c == '<' && next+3 < n && text[next+1] == '!' && text[next+2] == '-' && text[next+3] == '-' {
					searchStart := next + 4
					absEnd, ok := htmlCmtCache.findNext(searchStart)
					if !ok || absEnd-searchStart > maxInlineCommentSkipBytes {
						break
					}
					next = absEnd + 3
					continue
				}
				break
			}
			if extNext, extOK, extComma := skipExtendedSep(text, next, sawNewline, blockCmtCache, lineCmtCache, htmlCmtCache); extOK {
				next = extNext
				if extComma {
					segHasComma = true
				}
			}
			if next < n && (text[next] == '"' || text[next] == '\'' || text[next] == '`') {
				if segHasComma {
					sawCommaSeparator = true
				}
				if segHasPlusOrDot {
					sawPlusOrDot = true
				}
				pos = next
				continue
			}
			break
		}

		minSegments := 2
		if firstSegLen < 4 {
			minSegments = 8
		} else if firstSegLen < 8 {
			minSegments = 4
		}
		effectiveSegments := segments + templateSplits
		allUniformDigest := allUniformHexDigest || allUniformB64Digest
		if effectiveSegments >= minSegments && joined.Len() >= 64 {
			hasExplicitArrayJoin := false
			if sawCommaSeparator && !sawPlusOrDot && allUniformDigest {
				k := pos
				for k < n && (text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n' || text[k] == '}') {
					k++
				}
				if k < n && text[k] == ']' {
					k++
					afterEnd := min(n, k+96)
					stmtEnd := strings.IndexAny(text[k:afterEnd], ";\n")
					if stmtEnd >= 0 {
						afterEnd = k + stmtEnd
					}
					afterBracket := text[k:afterEnd]
					if strings.Contains(afterBracket, ".join(") || strings.Contains(afterBracket, ".reduce(") {
						hasExplicitArrayJoin = true
					} else {
						for k < n && (text[k] == ' ' || text[k] == '\t' || text[k] == '\r' || text[k] == '\n') {
							k++
						}
						if strings.HasPrefix(text[k:], ".join") {
							rem := strings.TrimLeft(text[k+len(".join"):], " \t\r\n")
							if strings.HasPrefix(rem, "(") {
								hasExplicitArrayJoin = true
							}
						} else if strings.HasPrefix(text[k:], ".reduce") {
							rem := strings.TrimLeft(text[k+len(".reduce"):], " \t\r\n")
							if strings.HasPrefix(rem, "(") {
								hasExplicitArrayJoin = true
							}
						}
					}
				}
				if !hasExplicitArrayJoin && hasJoinLookbehindOrVarJoin(text, i, pos) {
					hasExplicitArrayJoin = true
				}
			}
			joinedStr := joined.String()
			exemptDigestArray := false
			if sawCommaSeparator && !sawPlusOrDot && allUniformDigest && !hasExplicitArrayJoin {
				hasDigestCtx := hasDigestIdentifierContext(text, i, pos)
				isActionableOrUncontextualEntropy := func(dec []byte) bool {
					if isActionableDigestMasquerade(dec) {
						return true
					}
					if len(dec) >= minEntropyBytes {
						if _, highEnt := checkHighEntropy(dec); highEnt && !hasDigestCtx {
							return true
						}
					}
					return false
				}
				if dec, ok := decodeDigestArrayPayload(joinedStr, allUniformHexDigest); ok {
					if !isActionableOrUncontextualEntropy(dec) {
						if allUniformB64Digest {
							if perSeg, ok2 := decodeUniformB64Segments(segs); ok2 && isActionableOrUncontextualEntropy(perSeg) {
								joinedStr = base64.RawURLEncoding.EncodeToString(perSeg)
							} else {
								exemptDigestArray = true
							}
						} else {
							exemptDigestArray = true
						}
					}
				} else {
					handled := false
					if !allUniformHexDigest && len(joinedStr)%4 == 1 && len(joinedStr)-1 >= 64 {
						if dec, ok := decodeDigestArrayPayload(joinedStr[:len(joinedStr)-1], false); ok && isActionableOrUncontextualEntropy(dec) {
							joinedStr = joinedStr[:len(joinedStr)-1]
							handled = true
						}
					}
					if !handled && allUniformB64Digest {
						if perSeg, ok2 := decodeUniformB64Segments(segs); ok2 && isActionableOrUncontextualEntropy(perSeg) {
							joinedStr = base64.RawURLEncoding.EncodeToString(perSeg)
							handled = true
						}
					}
					if !handled {
						exemptDigestArray = true
					}
				}
			} else if allUniformB64Digest {
				// Even with explicit .join/.reduce, emit both len%4==1 stream decode and per-segment decode if direct stream decode fails or isn't actionable.
				if dec, ok := decodeDigestArrayPayload(joinedStr, false); !ok || !isActionableDecoded(dec) {
					emittedAlt := false
					if len(joinedStr)%4 == 1 && len(joinedStr)-1 >= 64 {
						if decTrim, okTrim := decodeDigestArrayPayload(joinedStr[:len(joinedStr)-1], false); okTrim && isActionableDecoded(decTrim) {
							results = append(results, joinedStr[:len(joinedStr)-1])
							emittedAlt = true
						}
					}
					if perSeg, ok2 := decodeUniformB64Segments(segs); ok2 && isActionableDigestMasquerade(perSeg) {
						results = append(results, base64.RawURLEncoding.EncodeToString(perSeg))
						emittedAlt = true
					}
					if emittedAlt {
						exemptDigestArray = true
					}
				}
			}
			if !exemptDigestArray {
				results = append(results, joinedStr)
			}
		}
		if pos > i {
			i = pos
		} else {
			i++
		}
	}
	return results
}

func tryDecodeBase64(raw string) ([]byte, bool) {
	if len(raw) > maxDecodedSegmentBytes*2 {
		return nil, false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if dec, err := enc.DecodeString(raw); err == nil && len(dec) >= 32 {
			if !isActionableDecoded(dec) {
				continue
			}
			return dec, true
		}
	}
	return nil, false
}

func inspectArchiveBuffer(
	ctx context.Context,
	virtualPath string,
	data []byte,
	magicKind string,
	archiveDepth int,
	decodeDepth int,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) bool {
	lower := strings.ToLower(virtualPath)
	switch {
	case magicKind == "zip" || strings.HasSuffix(lower, ".zip"):
		inspectZipArchive(ctx, virtualPath, data, archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		return true
	case magicKind == "gzip" || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".gz"):
		inspectGzipOrTarGz(ctx, virtualPath, data, archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		return true
	case magicKind == "tar" || strings.HasSuffix(lower, ".tar"):
		inspectTarArchive(ctx, virtualPath, bytes.NewReader(data), archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		return true
	default:
		return false
	}
}

func inspectZipArchive(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		res.ExtraSkipped++
		res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.corrupt-archive",
			domain.SeverityHigh,
			virtualPath,
			"corrupt or unreadable zip archive",
			map[string]any{
				"layer":     "L4_CONCEALMENT",
				"technique": "corrupt_archive",
				"format":    "zip",
			},
			"corrupt_zip",
		))
		return
	}

	for _, f := range zr.File {
		if ctx.Err() != nil {
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if err := validateArchiveRelPath(f.Name); err != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("unsafe_archive_entry:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.unsafe-archive-entry",
				domain.SeverityCritical,
				virtualPath,
				"unsafe path traversal in archive entry",
				map[string]any{
					"layer":     "L4_CONCEALMENT",
					"technique": "unsafe_archive_entry",
					"format":    "zip",
				},
				"unsafe_zip_path",
			))
			return
		}
		if f.Mode()&os.ModeSymlink != 0 || !f.Mode().IsRegular() && f.Mode() != 0 {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("unsafe_archive_entry:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.unsafe-archive-entry",
				domain.SeverityCritical,
				virtualPath,
				"symlink or non-regular entry in zip archive",
				map[string]any{
					"layer":     "L4_CONCEALMENT",
					"technique": "unsafe_archive_entry",
					"format":    "zip",
				},
				"unsafe_zip_mode",
			))
			return
		}
		budget.EntriesSeen++
		if budget.EntriesSeen > budget.MaxEntries {
			emitArchiveBomb(virtualPath, "zip", "max_entries_exceeded", budget, res)
			return
		}
		rc, err := f.Open()
		if err != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"failed opening zip archive entry",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "zip"},
				"corrupt_zip_entry",
			))
			return
		}
		entryBytes, bombed, readErr := readBoundedArchiveStream(rc, budget)
		_ = rc.Close()
		if bombed {
			emitArchiveBomb(virtualPath, "zip", "inflated_bytes_exceeded", budget, res)
			return
		}
		if readErr != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"corrupt zip entry stream",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "zip"},
				"corrupt_zip_stream",
			))
			return
		}

		entryPath := virtualPath + "!" + filepath.ToSlash(f.Name)
		inspectRecursiveL4(ctx, entryPath, entryBytes, archiveDepth+1, decodeDepth, true, inEncoded, budget, decodeRemaining, res)
	}
}

func inspectGzipOrTarGz(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		res.ExtraSkipped++
		res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.corrupt-archive",
			domain.SeverityHigh,
			virtualPath,
			"corrupt or unreadable gzip stream",
			map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "gzip"},
			"corrupt_gzip",
		))
		return
	}
	gzr.Multistream(true)
	defer func() { _ = gzr.Close() }()

	lower := strings.ToLower(virtualPath)
	isExplicitTarGz := strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
	if isExplicitTarGz {
		inspectMultiTarStream(ctx, virtualPath, gzr, archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		return
	}

	inflated, bombed, readErr := readBoundedArchiveStream(gzr, budget)
	if bombed {
		emitArchiveBomb(virtualPath, "gzip", "inflated_bytes_exceeded", budget, res)
		return
	}
	if readErr != nil {
		res.ExtraSkipped++
		res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.corrupt-archive",
			domain.SeverityHigh,
			virtualPath,
			"corrupt gzip stream payload",
			map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "gzip"},
			"corrupt_gzip_stream",
		))
		return
	}
	if len(inflated) >= 265 && bytes.Equal(inflated[257:262], []byte("ustar")) {
		inspectMultiTarStream(ctx, virtualPath, bytes.NewReader(inflated), archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		return
	}
	innerName := strings.TrimSuffix(virtualPath, filepath.Ext(virtualPath))
	if innerName == virtualPath || innerName == "" {
		innerName = virtualPath + "!gunzip"
	} else {
		innerName = virtualPath + "!" + filepath.Base(innerName)
	}
	inspectRecursiveL4(ctx, innerName, inflated, archiveDepth+1, decodeDepth, true, inEncoded, budget, decodeRemaining, res)
}

func inspectMultiTarStream(
	ctx context.Context,
	virtualPath string,
	r io.Reader,
	archiveDepth int,
	decodeDepth int,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	br := bufio.NewReaderSize(r, 32*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		beforeSkipped := res.ExtraSkipped
		inspectTarArchive(ctx, virtualPath, br, archiveDepth, decodeDepth, inEncoded, budget, decodeRemaining, res)
		if res.ExtraSkipped > beforeSkipped || ctx.Err() != nil {
			return
		}
		// Consume any trailing NUL padding blocks between concatenated tar/gzip members.
		for {
			b, err := br.ReadByte()
			if err == io.EOF {
				return
			}
			if err != nil {
				res.ExtraSkipped++
				res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.corrupt-archive",
					domain.SeverityHigh,
					virtualPath,
					"corrupt gzip stream payload",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "gzip"},
					"corrupt_gzip_stream",
				))
				return
			}
			budget.TotalInflated++
			if budget.TotalInflated > budget.MaxTotalInflatedBytes {
				emitArchiveBomb(virtualPath, "gzip", "inflated_bytes_exceeded", budget, res)
				return
			}
			if b != 0 {
				_ = br.UnreadByte()
				budget.TotalInflated--
				break
			}
		}
		hdrPeek, peekErr := br.Peek(265)
		if peekErr != nil && peekErr != io.EOF {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"corrupt gzip stream payload",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "gzip"},
				"corrupt_gzip_stream",
			))
			return
		}
		if len(hdrPeek) >= 265 && bytes.Equal(hdrPeek[257:262], []byte("ustar")) {
			continue
		}
		rem, bombed, readErr := readBoundedArchiveStream(br, budget)
		if bombed {
			emitArchiveBomb(virtualPath, "gzip", "inflated_bytes_exceeded", budget, res)
			return
		}
		if readErr != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"corrupt gzip stream payload",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "gzip"},
				"corrupt_gzip_stream",
			))
			return
		}
		if len(rem) > 0 {
			inspectRecursiveL4(ctx, virtualPath+"!trailing", rem, archiveDepth+1, decodeDepth, true, inEncoded, budget, decodeRemaining, res)
		}
		return
	}
}

func inspectTarArchive(
	ctx context.Context,
	virtualPath string,
	r io.Reader,
	archiveDepth int,
	decodeDepth int,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	tr := tar.NewReader(r)
	for {
		if ctx.Err() != nil {
			return
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"corrupt or truncated tar archive",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "tar"},
				"corrupt_tar",
			))
			return
		}
		if hdr.Size < 0 {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("unsafe_archive_entry:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.unsafe-archive-entry",
				domain.SeverityCritical,
				virtualPath,
				"negative entry size in tar archive",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "unsafe_archive_entry", "format": "tar"},
				"negative_tar_size",
			))
			return
		}
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("unsafe_archive_entry:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.unsafe-archive-entry",
				domain.SeverityCritical,
				virtualPath,
				"symlink, hardlink, or special device entry in tar archive",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "unsafe_archive_entry", "format": "tar"},
				"unsafe_tar_type",
			))
			return
		}
		if err := validateArchiveRelPath(hdr.Name); err != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("unsafe_archive_entry:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.unsafe-archive-entry",
				domain.SeverityCritical,
				virtualPath,
				"unsafe path traversal in tar entry",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "unsafe_archive_entry", "format": "tar"},
				"unsafe_tar_path",
			))
			return
		}
		budget.EntriesSeen++
		if budget.EntriesSeen > budget.MaxEntries {
			emitArchiveBomb(virtualPath, "tar", "max_entries_exceeded", budget, res)
			return
		}
		if hdr.Size > budget.MaxEntryInflatedBytes || budget.TotalInflated+hdr.Size > budget.MaxTotalInflatedBytes {
			emitArchiveBomb(virtualPath, "tar", "inflated_bytes_exceeded", budget, res)
			return
		}
		entryBytes, bombed, readErr := readBoundedArchiveStream(tr, budget)
		if bombed {
			emitArchiveBomb(virtualPath, "tar", "inflated_bytes_exceeded", budget, res)
			return
		}
		if readErr != nil {
			res.ExtraSkipped++
			res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("corrupt_archive:%s", sanitizeReasonPath(virtualPath)))
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.corrupt-archive",
				domain.SeverityHigh,
				virtualPath,
				"corrupt tar entry stream",
				map[string]any{"layer": "L4_CONCEALMENT", "technique": "corrupt_archive", "format": "tar"},
				"corrupt_tar_stream",
			))
			return
		}
		entryPath := virtualPath + "!" + filepath.ToSlash(hdr.Name)
		inspectRecursiveL4(ctx, entryPath, entryBytes, archiveDepth+1, decodeDepth, true, inEncoded, budget, decodeRemaining, res)
	}
}

func readBoundedArchiveStream(r io.Reader, budget *archiveBudget) ([]byte, bool, error) {
	remTotal := budget.MaxTotalInflatedBytes - budget.TotalInflated
	if remTotal <= 0 {
		return nil, true, nil
	}
	limit := budget.MaxEntryInflatedBytes
	if remTotal < limit {
		limit = remTotal
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return nil, true, nil
	}
	budget.TotalInflated += int64(len(buf))
	return buf, false, nil
}

func emitArchiveBomb(virtualPath, format, reason string, budget *archiveBudget, res *l4FileResult) {
	res.ExtraSkipped++
	res.SkippedReasons = append(res.SkippedReasons, fmt.Sprintf("archive_bomb_limit:%s", sanitizeReasonPath(virtualPath)))
	res.Findings = append(res.Findings, makeConcealmentFinding(
		"ip.l4.archive-limit-exceeded",
		domain.SeverityCritical,
		virtualPath,
		"archive exceeded bounded inflation or entry limits (fail-closed)",
		map[string]any{
			"layer":           "L4_CONCEALMENT",
			"technique":       "archive_bomb",
			"format":          format,
			"limit_reason":    reason,
			"max_entry_bytes": budget.MaxEntryInflatedBytes,
			"max_total_bytes": budget.MaxTotalInflatedBytes,
			"max_entries":     budget.MaxEntries,
		},
		fmt.Sprintf("%s:%s", format, reason),
	))
}

func validateArchiveRelPath(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.ContainsRune(name, '\\') {
		return fmt.Errorf("invalid archive path")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("absolute archive path")
	}
	if len(name) >= 2 && name[1] == ':' && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) {
		return fmt.Errorf("drive-prefixed archive path")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("unsafe archive path segment")
		}
	}
	return nil
}

func sanitizeReasonPath(p string) string {
	// Keep diagnostic reason bounded and stripped of control chars.
	p = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
	if len(p) > 160 {
		return p[:160]
	}
	return p
}

func checkHighEntropy(data []byte) (float64, bool) {
	return checkHighEntropyThresh(data, entropyThreshold)
}

func checkHighEntropyThresh(data []byte, thresh float64) (float64, bool) {
	if len(data) < minEntropyBytes {
		return 0, false
	}
	highPrintableThresh := max(thresh, entropyThresholdHighPrintable)
	maxEnt := 0.0
	if len(data) <= 1<<20 {
		ent, printableRatio := shannonEntropyAndPrintable(data)
		if ent >= thresh && (printableRatio < 0.85 || ent >= highPrintableThresh) {
			return ent, true
		}
		maxEnt = ent
	}
	if len(data) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(data) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(data); off += step {
			lastOff = off
			win := data[off : off+entropyWindowBytes]
			ent, printableRatio := shannonEntropyAndPrintable(win)
			if ent > maxEnt {
				maxEnt = ent
			}
			if ent >= thresh && (printableRatio < 0.85 || ent >= highPrintableThresh) {
				return ent, true
			}
		}
		tailOff := len(data) - entropyWindowBytes
		if tailOff > lastOff {
			win := data[tailOff:]
			ent, printableRatio := shannonEntropyAndPrintable(win)
			if ent > maxEnt {
				maxEnt = ent
			}
			if ent >= thresh && (printableRatio < 0.85 || ent >= highPrintableThresh) {
				return ent, true
			}
		}
	}
	return maxEnt, false
}

func shannonEntropy(data []byte) float64 {
	ent, _ := shannonEntropyAndPrintable(data)
	return ent
}

func shannonEntropyAndPrintable(data []byte) (float64, float64) {
	if len(data) == 0 {
		return 0, 0
	}
	var counts [256]int
	printable := 0
	for _, b := range data {
		counts[b]++
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	n := float64(len(data))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent, float64(printable) / n
}

func credentialRuleMayMatch(slug string, data []byte) bool {
	switch slug {
	case "private-key-block":
		return bytes.Contains(data, []byte("-----BEGIN"))
	case "github-token":
		return bytes.Contains(data, []byte("gh"))
	case "github-fine-grained-pat":
		return bytes.Contains(data, []byte("github_pat_"))
	case "gitlab-pat":
		return bytes.Contains(data, []byte("glpat-"))
	case "aws-access-key-id":
		return bytes.Contains(data, []byte("AKIA")) || bytes.Contains(data, []byte("ASIA"))
	case "api-sk-token":
		return bytes.Contains(data, []byte("sk-"))
	case "slack-token":
		return bytes.Contains(data, []byte("xox"))
	case "jwt-token":
		return bytes.Contains(data, []byte("eyJ"))
	case "x-access-token-url":
		const needle = "x-access-token:"
		if len(data) < len(needle) {
			return false
		}
		for i := 0; i <= len(data)-len(needle); i++ {
			if data[i] != 'x' && data[i] != 'X' {
				continue
			}
			if data[i+len(needle)-1] != ':' {
				continue
			}
			match := true
			for j := 1; j < len(needle)-1; j++ {
				c := data[i+j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c != needle[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func emitCredentialFindings(virtualPath string, data []byte, res *l4FileResult) {
	if len(data) == 0 || res == nil {
		return
	}
	var text string
	for _, rule := range concealmentCredentialRules {
		if !credentialRuleMayMatch(rule.slug, data) {
			continue
		}
		if text == "" {
			text = string(data)
		}
		matches := rule.re.FindAllString(text, 8)
		for _, m := range matches {
			if rule.slug == "api-sk-token" && (strings.HasPrefix(m, "sk-ssh-") || strings.HasPrefix(m, "sk-ecdsa-")) {
				continue
			}
			dig := domain.SHA256Hex([]byte(m))
			if res.seenCreds == nil {
				res.seenCreds = make(map[string]struct{})
			}
			credKey := virtualPath + "\x00" + rule.slug + "\x00" + dig
			if _, ok := res.seenCreds[credKey]; ok {
				continue
			}
			res.seenCreds[credKey] = struct{}{}
			fp := inspection.ComputeFingerprint(string(inspection.ScannerIPFingerprint), "ip.l4.secret."+rule.slug, virtualPath, 1, 1, dig)
			evID := inspection.ComputeEvidenceID(string(inspection.ScannerIPFingerprint), "SECRET", "ip.l4.secret."+rule.slug, virtualPath, 1, 1, fp)
			res.Findings = append(res.Findings, domain.Finding{
				Scanner:     string(inspection.ScannerIPFingerprint),
				EvidenceID:  evID,
				Category:    "SECRET",
				Severity:    domain.SeverityCritical,
				RuleID:      "ip.l4.secret." + rule.slug,
				Path:        virtualPath,
				StartLine:   1,
				EndLine:     1,
				Fingerprint: fp,
				Confidence:  0.95,
				Message:     fmt.Sprintf("Concealed credential pattern (%s) detected inside encoded/archived payload [REDACTED]", rule.slug),
				Redacted:    true,
				Metadata: map[string]any{
					"layer":         "L4_CONCEALMENT",
					"rule_slug":     rule.slug,
					"match_digest":  dig,
					"concealed_via": "l4",
				},
			})
		}
	}
}

func makeConcealmentFinding(
	ruleID string,
	severity domain.Severity,
	path string,
	msg string,
	meta map[string]any,
	materialKey string,
) domain.Finding {
	fp := inspection.ComputeFingerprint(string(inspection.ScannerIPFingerprint), ruleID, path, 1, 1, materialKey)
	evID := inspection.ComputeEvidenceID(string(inspection.ScannerIPFingerprint), "IP_CONCEALMENT", ruleID, path, 1, 1, fp)
	return domain.Finding{
		Scanner:     string(inspection.ScannerIPFingerprint),
		EvidenceID:  evID,
		Category:    "IP_CONCEALMENT",
		Severity:    severity,
		RuleID:      ruleID,
		Path:        path,
		StartLine:   1,
		EndLine:     1,
		Fingerprint: fp,
		Confidence:  0.95,
		Message:     msg,
		Redacted:    true,
		Metadata:    meta,
	}
}

func detectMagicKind(data []byte) (kind string, valid bool, spoofPrefixLen int) {
	if len(data) == 0 {
		return "", false, 0
	}
	// PNG signature: \x89PNG\r\n\x1a\n followed by full chunk chain (IHDR ... IDAT ... IEND@EOF with valid CRCs).
	pngSig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if bytes.HasPrefix(data, pngSig) {
		if isValidPNGStructure(data) {
			return "png", true, 0
		}
		return "png_invalid", false, 8
	}
	// JPEG: FF D8 FF followed by valid JPEG marker framing through SOS and FF D9 EOI at EOF.
	if len(data) >= 4 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		if isValidJPEGStructure(data) {
			return "jpeg", true, 0
		}
		return "jpeg_invalid", false, 3
	}
	// GIF
	if len(data) >= 14 && (bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))) {
		if isValidGIFStructure(data) {
			return "gif", true, 0
		}
		return "gif_invalid", false, 6
	}
	// WEBP
	if len(data) >= 12 && bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		if isValidWebPStructure(data) {
			return "webp", true, 0
		}
		return "webp_invalid", false, 12
	}
	// PDF
	if bytes.HasPrefix(data, []byte("%PDF-1.")) || bytes.HasPrefix(data, []byte("%PDF-2.")) {
		if isValidPDFStructure(data) {
			return "pdf", true, 0
		}
		return "pdf_invalid", false, 8
	}
	// WASM
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}) {
		if isValidWASMStructure(data) {
			return "wasm", true, 0
		}
		return "wasm_invalid", false, 8
	}
	// ELF
	if len(data) >= 16 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return "elf", true, 0
	}
	// Mach-O (32/64 LE/BE + fat binary with nfat_arch < 20)
	if len(data) >= 28 {
		magic := binary.BigEndian.Uint32(data[:4])
		switch magic {
		case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
			return "macho", true, 0
		case 0xCAFEBABE:
			nfat := binary.BigEndian.Uint32(data[4:8])
			if nfat > 0 && nfat < 20 {
				return "macho", true, 0
			}
		}
	}
	// PE/COFF (MZ + e_lfanew -> PE\x00\x00)
	if len(data) >= 64 && data[0] == 'M' && data[1] == 'Z' {
		lfanew := binary.LittleEndian.Uint32(data[60:64])
		if int(lfanew)+4 <= len(data) && bytes.Equal(data[lfanew:lfanew+4], []byte{'P', 'E', 0, 0}) {
			return "pe", true, 0
		}
	}
	// ZIP
	if len(data) >= 4 && (bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) || bytes.Equal(data[:4], []byte{'P', 'K', 5, 6}) || bytes.Equal(data[:4], []byte{'P', 'K', 7, 8})) {
		return "zip", true, 0
	}
	// GZIP
	if len(data) >= 10 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08 {
		return "gzip", true, 0
	}
	// TAR
	if len(data) >= 265 && bytes.Equal(data[257:262], []byte("ustar")) {
		return "tar", true, 0
	}
	// ICC color profile ('acsp' signature at offset 36, validated header & tag table)
	if len(data) >= 132 && bytes.Equal(data[36:40], []byte("acsp")) {
		if isValidICCProfileHeaderAndTags(data) {
			return "icc", true, 0
		}
	}
	// SFNT font (.ttf / .otf) and TrueType Collection (.ttc)
	if len(data) >= 12 {
		sfntTag := binary.BigEndian.Uint32(data[0:4])
		if sfntTag == 0x00010000 || sfntTag == 0x4F54544F || sfntTag == 0x74727565 || sfntTag == 0x74797031 {
			if isValidSFNTFont(data) {
				return "sfnt", true, 0
			}
		}
		if bytes.Equal(data[0:4], []byte("ttcf")) && isValidTTCFCollection(data) {
			return "ttc", true, 0
		}
	}
	return "", false, 0
}

func checkMagicExtensionMismatch(ext string, data []byte, magicKind string, magicValid bool) (bool, string) {
	if isTextOrSourceExt(ext) {
		if magicKind != "" {
			return true, magicKind + "_in_text"
		}
		if hasDisallowedControlBytes(data) && !isValidUTF16Text(data) {
			if bytes.IndexByte(data, 0) >= 0 {
				return true, "nul_bytes_in_text"
			}
			return true, "control_bytes_in_text"
		}
		if hasSuspiciousVerticalControlInterleaving(data) && !isValidUTF16Text(data) {
			return true, "control_bytes_in_text"
		}
		return false, ""
	}
	switch ext {
	case ".png":
		if magicKind != "png" || !magicValid {
			return true, "invalid_png_structure"
		}
	case ".jpg", ".jpeg":
		if magicKind != "jpeg" || !magicValid {
			return true, "invalid_jpeg_structure"
		}
	case ".gif":
		if magicKind != "gif" || !magicValid {
			return true, "invalid_gif_structure"
		}
	case ".webp":
		if magicKind != "webp" || !magicValid {
			return true, "invalid_webp_structure"
		}
	case ".pdf":
		if magicKind != "pdf" || !magicValid {
			return true, "invalid_pdf_structure"
		}
	case ".wasm":
		if magicKind != "wasm" || !magicValid {
			return true, "invalid_wasm_structure"
		}
	case ".exe", ".dll":
		if magicKind != "pe" {
			return true, "invalid_pe_structure"
		}
	case ".so":
		if magicKind != "elf" {
			return true, "invalid_elf_structure"
		}
	case ".dylib":
		if magicKind != "macho" {
			return true, "invalid_macho_structure"
		}
	case ".zip":
		if magicKind != "zip" {
			return true, "invalid_zip_magic"
		}
	case ".gz", ".tgz":
		if magicKind != "gzip" {
			return true, "invalid_gzip_magic"
		}
	case ".tar":
		if magicKind != "tar" {
			return true, "invalid_tar_magic"
		}
	case ".icc", ".icm":
		if magicKind != "icc" || !magicValid {
			return true, "invalid_icc_structure"
		}
	case ".ttf", ".otf":
		if magicKind != "sfnt" || !magicValid {
			return true, "invalid_sfnt_structure"
		}
	case ".ttc":
		if (magicKind != "ttc" && magicKind != "sfnt") || !magicValid {
			return true, "invalid_ttc_structure"
		}
	case ".bin", ".dat":
		if len(data) >= 32 && (hasHighPrintableAscii(data) || hasSignificantPrintableText(data)) {
			return true, "text_disguised_as_binary"
		}
		if (hasDisallowedControlBytes(data) || hasSuspiciousVerticalControlInterleaving(data)) && !isValidUTF16Text(data) {
			stripped := stripControlBytesForInspection(data)
			if len(stripped) >= 64 && utf8.Valid(stripped) && hasHighPrintableAscii(stripped) && hasSignificantPrintableText(stripped) {
				return true, "text_disguised_as_binary"
			}
		}
	case "":
		if magicKind == "" && (hasDisallowedControlBytes(data) || hasSuspiciousVerticalControlInterleaving(data)) && !isValidUTF16Text(data) {
			stripped := stripControlBytesForInspection(data)
			if len(stripped) >= 64 && utf8.Valid(stripped) && hasHighPrintableAscii(stripped) && hasSignificantPrintableText(stripped) {
				return true, "text_disguised_as_binary"
			}
		}
	}
	return false, ""
}

func isTextOrSourceExt(ext string) bool {
	switch ext {
	case ".txt", ".md", ".markdown", ".go", ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs",
		".ts", ".tsx", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java", ".rs",
		".cs", ".kt", ".kts", ".swift", ".scala", ".rb", ".php", ".sh", ".bash", ".zsh",
		".json", ".yaml", ".yml", ".toml", ".xml", ".html", ".htm", ".css", ".scss",
		".sql", ".csv", ".ini", ".cfg", ".conf", ".env",
		".proto", ".tf", ".hcl", ".lua", ".dart", ".sol", ".zig", ".vue", ".svelte",
		".graphql", ".gql", ".r", ".jl", ".ex", ".exs", ".erl", ".hs", ".ml", ".clj",
		".nix", ".cmake", ".gradle", ".groovy", ".pl", ".pm", ".ps1", ".bat", ".awk", ".sed":
		return true
	default:
		return false
	}
}

func isArchiveExtension(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".tar") ||
		strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tgz") ||
		strings.HasSuffix(lower, ".gz")
}

func isExemptFromEntropy(magicKind string, magicValid bool) bool {
	if !magicValid {
		return false
	}
	switch magicKind {
	case "png", "jpeg", "gif", "webp", "pdf", "wasm", "icc", "sfnt", "ttc":
		return true
	default:
		return false
	}
}

func isExecutableOrArchiveMagic(data []byte) bool {
	kind, _, _ := detectMagicKind(data)
	switch kind {
	case "elf", "macho", "pe", "zip", "gzip", "tar", "wasm":
		return true
	default:
		return false
	}
}

func hasHighPrintableAscii(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	printable := 0
	for _, b := range data[:limit] {
		if isDisallowedControlByte(b) {
			return false
		}
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(limit) >= 0.85
}

func hasSignificantPrintableText(data []byte) bool {
	extracted := extractPrintableTextRuns(data, 32)
	if len(extracted) >= 128 {
		return true
	}
	return len(extracted) >= 48 && bytes.IndexByte(extracted, '\n') >= 0
}

func extractPrintableTextRuns(data []byte, minRunBytes int) []byte {
	if len(data) == 0 || minRunBytes <= 0 {
		return nil
	}
	var out bytes.Buffer
	runStart := -1
	i := 0
	flushRun := func(end int) {
		if runStart >= 0 && end-runStart >= minRunBytes {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.Write(data[runStart:end])
		}
		runStart = -1
	}
	for i < len(data) {
		b := data[i]
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			if runStart < 0 {
				runStart = i
			}
			i++
			continue
		}
		if b >= 0x80 {
			r, size := utf8.DecodeRune(data[i:])
			if r != utf8.RuneError && size > 1 && !unicode.IsControl(r) {
				if runStart < 0 {
					runStart = i
				}
				i += size
				continue
			}
		}
		flushRun(i)
		i++
	}
	flushRun(len(data))
	if out.Len() == 0 {
		return nil
	}
	return out.Bytes()
}

func isValidUTF16Text(data []byte) bool {
	_, ok := decodeUTF16Text(data)
	return ok
}

func decodeUTF16Text(data []byte) ([]byte, bool) {
	if len(data) < 4 || len(data)%2 != 0 {
		return nil, false
	}
	var littleEndian bool
	switch {
	case data[0] == 0xFF && data[1] == 0xFE:
		littleEndian = true
	case data[0] == 0xFE && data[1] == 0xFF:
		littleEndian = false
	default:
		return decodeBOMlessUTF16Text(data)
	}
	payload := data[2:]
	if len(payload) >= 4 && payload[len(payload)-2] == 0 && payload[len(payload)-1] == 0 {
		payload = payload[:len(payload)-2]
	}
	u16 := make([]uint16, len(payload)/2)
	for i := 0; i < len(u16); i++ {
		if littleEndian {
			u16[i] = binary.LittleEndian.Uint16(payload[i*2 : i*2+2])
		} else {
			u16[i] = binary.BigEndian.Uint16(payload[i*2 : i*2+2])
		}
		if u16[i] == 0 {
			return nil, false
		}
	}
	runes := utf16.Decode(u16)
	if len(runes) == 0 {
		return nil, false
	}
	printable := 0
	asciiOrLatin := 0
	for _, r := range runes {
		if r == 0 || r == utf8.RuneError {
			return nil, false
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return nil, false
		}
		if r >= 0x7f && r <= 0x9f {
			return nil, false
		}
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
		if r < 0x100 {
			asciiOrLatin++
		}
	}
	if float64(printable)/float64(len(runes)) < 0.85 || asciiOrLatin == 0 {
		return nil, false
	}
	return []byte(string(runes)), true
}

func decodeBOMlessUTF16Text(data []byte) ([]byte, bool) {
	if len(data) < 16 || len(data)%2 != 0 {
		return nil, false
	}
	if (data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF) {
		return nil, false
	}
	if kind, _, _ := detectMagicKind(data); kind != "" {
		return nil, false
	}
	if len(data) >= 18 && data[len(data)-2] == 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-2]
	}
	tryOrder := func(littleEndian bool) ([]byte, bool) {
		nUnits := len(data) / 2
		u16 := make([]uint16, nUnits)
		asciiRange := 0
		for i := 0; i < nUnits; i++ {
			var lo, hi byte
			if littleEndian {
				lo = data[2*i]
				hi = data[2*i+1]
				u16[i] = uint16(lo) | (uint16(hi) << 8)
			} else {
				hi = data[2*i]
				lo = data[2*i+1]
				u16[i] = (uint16(hi) << 8) | uint16(lo)
			}
			if u16[i] == 0 {
				return nil, false
			}
			if hi == 0x00 && ((lo >= 0x20 && lo <= 0x7e) || lo == '\n' || lo == '\r' || lo == '\t') {
				asciiRange++
			}
		}
		if len(data) < 32 {
			if asciiRange*100 < nUnits*85 {
				return nil, false
			}
		} else if asciiRange*100 <= nUnits*80 {
			return nil, false
		}
		for i := 0; i < len(u16); i++ {
			c := u16[i]
			if c >= 0xD800 && c <= 0xDBFF {
				if i+1 >= len(u16) || u16[i+1] < 0xDC00 || u16[i+1] > 0xDFFF {
					return nil, false
				}
				i++
			} else if c >= 0xDC00 && c <= 0xDFFF {
				return nil, false
			}
		}
		runes := utf16.Decode(u16)
		for _, r := range runes {
			if r == 0 || r == utf8.RuneError {
				return nil, false
			}
			if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
				return nil, false
			}
			if r >= 0x7f && r <= 0x9f {
				return nil, false
			}
		}
		return []byte(string(runes)), true
	}
	if out, ok := tryOrder(true); ok {
		return out, true
	}
	if out, ok := tryOrder(false); ok {
		return out, true
	}
	return nil, false
}

func extractLossyUTF16ForCredentials(data []byte) [][]byte {
	if len(data) < 16 {
		return nil
	}
	evenLen := len(data) &^ 1
	if evenLen < 16 {
		return nil
	}
	evenZero := 0
	oddZero := 0
	for i := 0; i < evenLen; i += 2 {
		if data[i] == 0 {
			evenZero++
		}
		if data[i+1] == 0 {
			oddZero++
		}
	}
	var out [][]byte
	decodeEndian := func(le bool) []byte {
		u16 := make([]uint16, evenLen/2)
		for i := 0; i < len(u16); i++ {
			if le {
				u16[i] = binary.LittleEndian.Uint16(data[2*i : 2*i+2])
			} else {
				u16[i] = binary.BigEndian.Uint16(data[2*i : 2*i+2])
			}
		}
		return []byte(string(utf16.Decode(u16)))
	}
	if oddZero >= 4 {
		out = append(out, decodeEndian(true))
	}
	if evenZero >= 4 {
		out = append(out, decodeEndian(false))
	}
	return out
}

func stripWrappedCommentLine(trimmed string) (cleaned string, skipWrapper bool) {
	if trimmed == "" {
		return "", false
	}
	if trimmed == "/*" || trimmed == "*/" || trimmed == "*" || trimmed == "//" || trimmed == "#" || trimmed == "--" || trimmed == "|" || trimmed == "<!--" || trimmed == "-->" {
		return "", true
	}
	s := trimmed
	for {
		prev := s
		s = strings.TrimSpace(strings.TrimPrefix(s, "<!--"))
		s = strings.TrimSpace(strings.TrimSuffix(s, "-->"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "/*"))
		s = strings.TrimSpace(strings.TrimSuffix(s, "*/"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "//"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "#"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "--"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "*"))
		s = strings.TrimSpace(strings.TrimPrefix(s, "|"))
		s = strings.TrimSpace(strings.TrimSuffix(s, "|"))
		if s == prev {
			break
		}
	}
	if s == "" {
		return "", true
	}
	return s, false
}

type countingByteReader struct {
	b   []byte
	pos int
}

func (r *countingByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func (r *countingByteReader) ReadByte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func hasDecodedImageSpatialCorrelation(img image.Image) bool {
	if img == nil {
		return false
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 16 || h < 16 || int64(w)*int64(h) < 256 || int64(w)*int64(h) > 16_000_000 {
		return true
	}
	checkChannel := func(ch []byte) bool {
		if len(ch) < minEntropyBytes {
			return true
		}
		var sumDiff uint64
		var cnt uint64
		for y := 0; y < h; y++ {
			rowOff := y * w
			for x := 1; x < w; x++ {
				d := int(ch[rowOff+x]) - int(ch[rowOff+x-1])
				if d < 0 {
					d = -d
				}
				sumDiff += uint64(d)
				cnt++
			}
			if y > 0 {
				prevOff := (y - 1) * w
				for x := 0; x < w; x++ {
					d := int(ch[rowOff+x]) - int(ch[prevOff+x])
					if d < 0 {
						d = -d
					}
					sumDiff += uint64(d)
					cnt++
				}
			}
		}
		if cnt == 0 {
			return true
		}
		avgDiff := float64(sumDiff) / float64(cnt)
		if avgDiff > 55 && zlibCompressedRatio(ch) >= 0.90 {
			return false
		}
		return true
	}
	switch m := img.(type) {
	case *image.Paletted:
		idx := make([]byte, w*h)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				idx[y*w+x] = m.ColorIndexAt(b.Min.X+x, b.Min.Y+y)
			}
		}
		return checkChannel(idx)
	case *image.Gray:
		ch := make([]byte, w*h)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				ch[y*w+x] = m.GrayAt(b.Min.X+x, b.Min.Y+y).Y
			}
		}
		return checkChannel(ch)
	case *image.Gray16:
		ch := make([]byte, w*h)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				ch[y*w+x] = byte(m.Gray16At(b.Min.X+x, b.Min.Y+y).Y >> 8)
			}
		}
		return checkChannel(ch)
	default:
		rCh := make([]byte, w*h)
		gCh := make([]byte, w*h)
		bCh := make([]byte, w*h)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
				idx := y*w + x
				rCh[idx] = byte(r >> 8)
				gCh[idx] = byte(g >> 8)
				bCh[idx] = byte(bl >> 8)
			}
		}
		return checkChannel(rCh) && checkChannel(gCh) && checkChannel(bCh)
	}
}

func isValidGIFStructure(data []byte) bool {
	if len(data) < 14 || (!bytes.HasPrefix(data, []byte("GIF87a")) && !bytes.HasPrefix(data, []byte("GIF89a"))) {
		return false
	}
	if data[len(data)-1] != ';' {
		return false
	}
	if hasHighPrintableAscii(data[6:]) || len(extractPrintableTextRuns(data[6:], 48)) > 0 {
		return false
	}
	pos := 13
	packed := data[10]
	if packed&0x80 != 0 {
		gctSize := 3 * (1 << ((packed & 0x07) + 1))
		if pos+gctSize > len(data) {
			return false
		}
		pos += gctSize
	}
	seenImage := false
	for pos < len(data) {
		intro := data[pos]
		pos++
		switch intro {
		case 0x3B: // Trailer
			if pos != len(data) || !seenImage {
				return false
			}
			ga, err := gif.DecodeAll(bytes.NewReader(data))
			if err != nil || len(ga.Image) == 0 {
				return false
			}
			for _, frame := range ga.Image {
				if !hasDecodedImageSpatialCorrelation(frame) {
					return false
				}
			}
			return true
		case 0x21: // Extension
			if pos >= len(data) {
				return false
			}
			label := data[pos]
			pos++
			var extData bytes.Buffer
			for {
				if pos >= len(data) {
					return false
				}
				subLen := int(data[pos])
				pos++
				if subLen == 0 {
					break
				}
				if pos+subLen > len(data) {
					return false
				}
				if label == 0xFE || label == 0xFF {
					extData.Write(data[pos : pos+subLen])
				}
				pos += subLen
			}
			if (label == 0xFE || label == 0xFF) && extData.Len() >= minEntropyBytes {
				eb := extData.Bytes()
				if hasConcealedHighEntropy(eb) || hasBitAgnosticIncompressible(eb, 5.80, 0.88) || hasHighPrintableAscii(eb) {
					return false
				}
			}
		case 0x2C: // Image Descriptor
			if pos+9 > len(data) {
				return false
			}
			imgPacked := data[pos+8]
			pos += 9
			if imgPacked&0x80 != 0 {
				lctSize := 3 * (1 << ((imgPacked & 0x07) + 1))
				if pos+lctSize > len(data) {
					return false
				}
				pos += lctSize
			}
			if pos >= len(data) {
				return false
			}
			lzwMin := data[pos]
			pos++
			if lzwMin < 2 || lzwMin > 12 {
				return false
			}
			for {
				if pos >= len(data) {
					return false
				}
				subLen := int(data[pos])
				pos++
				if subLen == 0 {
					break
				}
				if pos+subLen > len(data) {
					return false
				}
				pos += subLen
			}
			seenImage = true
		default:
			return false
		}
	}
	return false
}

func isValidPNGStructure(data []byte) bool {
	if len(data) < 8+12+13+12 {
		return false
	}
	off := 8
	seenIHDR := false
	seenIDAT := false
	seenIEND := false
	var idatBuf bytes.Buffer
	for off < len(data) {
		if seenIEND {
			return false
		}
		if off+12 > len(data) {
			return false
		}
		chunkLen := binary.BigEndian.Uint32(data[off : off+4])
		if uint64(chunkLen) > uint64(len(data)-off-12) {
			return false
		}
		chunkType := data[off+4 : off+8]
		for _, b := range chunkType {
			if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) {
				return false
			}
		}
		expectedCRC := crc32.ChecksumIEEE(data[off+4 : off+8+int(chunkLen)])
		actualCRC := binary.BigEndian.Uint32(data[off+8+int(chunkLen) : off+12+int(chunkLen)])
		if expectedCRC != actualCRC {
			return false
		}
		typeStr := string(chunkType)
		if !seenIHDR {
			if typeStr != "IHDR" || chunkLen != 13 {
				return false
			}
			seenIHDR = true
		} else if typeStr == "IHDR" {
			return false
		}
		switch typeStr {
		case "IDAT":
			seenIDAT = true
			if idatBuf.Len()+int(chunkLen) > defaultArchiveMaxTotalBytes {
				return false
			}
			idatBuf.Write(data[off+8 : off+8+int(chunkLen)])
		case "IEND":
			if chunkLen != 0 {
				return false
			}
			seenIEND = true
		}
		off += 12 + int(chunkLen)
	}
	if off != len(data) || !seenIHDR || !seenIDAT || !seenIEND {
		return false
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return false
	}
	cbr := &countingByteReader{b: idatBuf.Bytes()}
	zr, zErr := zlib.NewReader(cbr)
	if zErr != nil {
		return false
	}
	_, rErr := io.Copy(io.Discard, io.LimitReader(zr, defaultArchiveMaxTotalBytes+1))
	_ = zr.Close()
	if rErr != nil || cbr.pos != idatBuf.Len() {
		return false
	}
	return hasDecodedImageSpatialCorrelation(img)
}

func inspectPNGChunks(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if len(data) < 8+12 {
		return
	}
	off := 8
	for off+12 <= len(data) {
		chunkLen := binary.BigEndian.Uint32(data[off : off+4])
		if uint64(chunkLen) > uint64(len(data)-off-12) {
			return
		}
		typeStr := string(data[off+4 : off+8])
		payload := data[off+8 : off+8+int(chunkLen)]
		off += 12 + int(chunkLen)

		switch typeStr {
		case "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "sBIT", "sRGB", "bKGD", "hIST", "pHYs", "sPLT", "tIME":
			continue
		case "iCCP":
			if !inspectPNGICCPChunk(ctx, virtualPath, payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res) {
				return
			}
			continue
		case "eXIf":
			inspectExifPayload(ctx, virtualPath, "#png_eXIf", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			continue
		case "zTXt":
			nulIdx := bytes.IndexByte(payload, 0)
			if nulIdx < 1 || nulIdx > 79 || nulIdx+2 > len(payload) || payload[nulIdx+1] != 0 {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid PNG zTXt chunk header",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_ztxt"},
					"invalid_png_ztxt",
				))
				inspectAncillaryPayload(ctx, virtualPath, "#png_ztxt", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
				continue
			}
			comp := payload[nulIdx+2:]
			zr, err := zlib.NewReader(bytes.NewReader(comp))
			if err != nil {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid zlib stream inside PNG zTXt chunk",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_ztxt"},
					"invalid_png_ztxt_zlib",
				))
				inspectAncillaryPayload(ctx, virtualPath, "#png_ztxt", comp, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
				continue
			}
			dec, bombed, readErr := readBoundedArchiveStream(zr, budget)
			_ = zr.Close()
			if bombed {
				emitArchiveBomb(virtualPath, "png_ztxt", "inflated_bytes_exceeded", budget, res)
				return
			}
			if readErr != nil {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"corrupt zlib stream inside PNG zTXt chunk",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_ztxt"},
					"corrupt_png_ztxt_zlib",
				))
				continue
			}
			if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
				inspectRecursiveL4(ctx, virtualPath+"#png_ztxt", dec, archiveDepth, decodeDepth+1, inArchive, true, budget, decodeRemaining, res)
			} else {
				inspectAncillaryPayload(ctx, virtualPath, "#png_ztxt", dec, archiveDepth, decodeDepth, inArchive, true, budget, decodeRemaining, res)
				if isExecutableOrArchiveMagic(dec) {
					res.Findings = append(res.Findings, makeConcealmentFinding(
						"ip.l4.encoded-payload",
						domain.SeverityHigh,
						virtualPath,
						"nested binary/archive payload inside PNG zTXt chunk exceeded decode depth",
						map[string]any{"layer": "L4_CONCEALMENT", "technique": "encoded_payload", "encoding": "png_ztxt", "decoded_bytes": len(dec)},
						"png_ztxt_depth:"+domain.SHA256Hex(dec),
					))
				}
			}
		case "iTXt":
			nul1 := bytes.IndexByte(payload, 0)
			if nul1 < 1 || nul1 > 79 || nul1+3 > len(payload) {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid PNG iTXt chunk header",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
					"invalid_png_itxt",
				))
				continue
			}
			compFlag := payload[nul1+1]
			compMethod := payload[nul1+2]
			rest := payload[nul1+3:]
			nul2 := bytes.IndexByte(rest, 0)
			if nul2 < 0 {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid PNG iTXt language tag",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
					"invalid_png_itxt_lang",
				))
				continue
			}
			rest = rest[nul2+1:]
			nul3 := bytes.IndexByte(rest, 0)
			if nul3 < 0 {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid PNG iTXt translated keyword",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
					"invalid_png_itxt_trans",
				))
				continue
			}
			textBytes := rest[nul3+1:]
			if compFlag == 1 {
				if compMethod != 0 {
					res.Findings = append(res.Findings, makeConcealmentFinding(
						"ip.l4.magic-byte-mismatch",
						domain.SeverityHigh,
						virtualPath,
						"unsupported PNG iTXt compression method",
						map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
						"invalid_png_itxt_method",
					))
					continue
				}
				zr, err := zlib.NewReader(bytes.NewReader(textBytes))
				if err != nil {
					res.Findings = append(res.Findings, makeConcealmentFinding(
						"ip.l4.magic-byte-mismatch",
						domain.SeverityHigh,
						virtualPath,
						"invalid zlib stream inside PNG iTXt chunk",
						map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
						"invalid_png_itxt_zlib",
					))
					inspectAncillaryPayload(ctx, virtualPath, "#png_itxt", textBytes, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					continue
				}
				dec, bombed, readErr := readBoundedArchiveStream(zr, budget)
				_ = zr.Close()
				if bombed {
					emitArchiveBomb(virtualPath, "png_itxt", "inflated_bytes_exceeded", budget, res)
					return
				}
				if readErr != nil {
					res.Findings = append(res.Findings, makeConcealmentFinding(
						"ip.l4.magic-byte-mismatch",
						domain.SeverityHigh,
						virtualPath,
						"corrupt zlib stream inside PNG iTXt chunk",
						map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
						"corrupt_png_itxt_zlib",
					))
					continue
				}
				if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
					inspectRecursiveL4(ctx, virtualPath+"#png_itxt", dec, archiveDepth, decodeDepth+1, inArchive, true, budget, decodeRemaining, res)
				} else {
					inspectAncillaryPayload(ctx, virtualPath, "#png_itxt", dec, archiveDepth, decodeDepth, inArchive, true, budget, decodeRemaining, res)
					if isExecutableOrArchiveMagic(dec) {
						res.Findings = append(res.Findings, makeConcealmentFinding(
							"ip.l4.encoded-payload",
							domain.SeverityHigh,
							virtualPath,
							"nested binary/archive payload inside PNG iTXt chunk exceeded decode depth",
							map[string]any{"layer": "L4_CONCEALMENT", "technique": "encoded_payload", "encoding": "png_itxt", "decoded_bytes": len(dec)},
							"png_itxt_depth:"+domain.SHA256Hex(dec),
						))
					}
				}
			} else if compFlag == 0 {
				inspectAncillaryPayload(ctx, virtualPath, "#png_iTXt", textBytes, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			} else {
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.magic-byte-mismatch",
					domain.SeverityHigh,
					virtualPath,
					"invalid PNG iTXt compression flag",
					map[string]any{"layer": "L4_CONCEALMENT", "technique": "magic_byte_mismatch", "detected_magic": "invalid_png_itxt"},
					"invalid_png_itxt_flag",
				))
			}
		default:
			inspectAncillaryPayload(ctx, virtualPath, "#png_"+typeStr, payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		}
	}
}

func inspectPNGICCPChunk(
	ctx context.Context,
	virtualPath string,
	payload []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) bool {
	nulIdx := bytes.IndexByte(payload, 0)
	if nulIdx < 1 || nulIdx > 79 || nulIdx+2 > len(payload) || payload[nulIdx+1] != 0 {
		inspectAncillaryPayload(ctx, virtualPath, "#png_iCCP", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		return true
	}
	comp := payload[nulIdx+2:]
	zr, err := zlib.NewReader(bytes.NewReader(comp))
	if err != nil {
		inspectAncillaryPayload(ctx, virtualPath, "#png_iCCP", comp, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		return true
	}
	iccData, bombed, readErr := readBoundedArchiveStream(zr, budget)
	_ = zr.Close()
	if bombed {
		emitArchiveBomb(virtualPath, "png_iccp", "inflated_bytes_exceeded", budget, res)
		return false
	}
	if readErr != nil || !isValidICCProfileHeaderAndTags(iccData) {
		target := iccData
		if readErr != nil || len(target) == 0 {
			target = comp
		}
		inspectAncillaryPayload(ctx, virtualPath, "#png_iCCP", target, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		return true
	}
	inspectValidatedICCProfile(ctx, virtualPath, "#png_iCCP", iccData, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	return true
}

func isValidICCColorSpace(cs string) bool {
	switch cs {
	case "XYZ ", "Lab ", "Luv ", "YCbr", "Yxy ", "RGB ", "GRAY", "HSV ", "HLS ", "CMYK", "CMY ":
		return true
	}
	if len(cs) == 4 && cs[1:] == "CLR" && ((cs[0] >= '2' && cs[0] <= '9') || (cs[0] >= 'A' && cs[0] <= 'F')) {
		return true
	}
	return false
}

func isMonotonicUint16Slice(b []byte, cnt int) bool {
	if cnt < 2 || len(b) < cnt*2 {
		return true
	}
	nonDec := 0
	nonInc := 0
	prev := binary.BigEndian.Uint16(b[0:2])
	for i := 1; i < cnt; i++ {
		cur := binary.BigEndian.Uint16(b[i*2 : i*2+2])
		if cur < prev {
			nonDec++
		}
		if cur > prev {
			nonInc++
		}
		prev = cur
	}
	return min(nonDec, nonInc) <= max(2, cnt/16)
}

func isMonotonicByteTable(b []byte) bool {
	if len(b) < 2 {
		return true
	}
	nonDec := 0
	nonInc := 0
	for i := 1; i < len(b); i++ {
		if b[i] < b[i-1] {
			nonDec++
		}
		if b[i] > b[i-1] {
			nonInc++
		}
	}
	return min(nonDec, nonInc) <= max(2, len(b)/16)
}

func isSmoothCLUT8(clut []byte, outC int) bool {
	if len(clut) < 256 || outC <= 0 || len(clut) <= outC {
		return true
	}
	numPts := len(clut) / outC
	if numPts < 2 {
		return true
	}
	checkSeq := func(seq []byte) bool {
		if len(seq) < 2 {
			return true
		}
		var sum uint64
		for i := 1; i < len(seq); i++ {
			d := int(seq[i]) - int(seq[i-1])
			if d < 0 {
				d = -d
			}
			sum += uint64(d)
		}
		return sum/uint64(len(seq)-1) < 55
	}
	ch := make([]byte, numPts)
	nz := make([]byte, 0, numPts)
	sc := make([]byte, 0, numPts)
	checkSeqWindows := func(seq []byte) bool {
		if !checkSeq(seq) {
			return false
		}
		if len(seq)-1 >= 128 {
			win := min(256, max(64, len(seq)/4))
			step := max(1, win/2)
			for off := 0; off+win <= len(seq); off += step {
				if !checkSeq(seq[off : off+win]) {
					return false
				}
			}
			if len(seq) > win && !checkSeq(seq[len(seq)-win:]) {
				return false
			}
		}
		return true
	}
	for c := 0; c < outC; c++ {
		nz = nz[:0]
		sc = sc[:0]
		for i := 0; i < numPts; i++ {
			v := clut[i*outC+c]
			ch[i] = v
			if v != 0 {
				nz = append(nz, v)
			}
			if !isDisallowedControlByte(v) {
				sc = append(sc, v)
			}
		}
		if !checkSeqWindows(ch) {
			return false
		}
		if len(nz) >= 128 && !checkSeqWindows(nz) {
			return false
		}
		if len(sc) >= 128 && !checkSeqWindows(sc) {
			return false
		}
		if dom, ok := stripDominantByteIfOver(ch, 20); ok && len(dom) >= 128 && !checkSeqWindows(dom) {
			return false
		}
		if domK, ok := stripTopKBytes(ch, 8, 4, 25); ok && len(domK) >= 128 && !checkSeqWindows(domK) {
			return false
		}
		if nb, ok := stripNarrowBandBytes(ch, 32, 0.40); ok && len(nb) >= minEntropyBytes {
			if hasConcealedHighEntropy(nb) {
				return false
			}
			if e, _ := shannonEntropyAndPrintable(nb); seqAvgDiff(nb) >= 55 && e >= 6.40 && zlibCompressedRatio(nb) >= 0.85 {
				return false
			}
		}
		if mp, ok := stripTopKMultiPad(ch, 32, 0.40); ok && len(mp) >= minEntropyBytes {
			if e, _ := shannonEntropyAndPrintable(mp); seqAvgDiff(mp) >= 55 && e >= 6.40 && zlibCompressedRatio(mp) >= 0.85 {
				return false
			}
		}
		if pCol := collapseRepeatedPeriodic(ch, 32, 4); len(pCol) >= 128 && len(pCol) < len(ch)*9/10 && !checkSeqWindows(pCol) {
			if hasConcealedHighEntropyThresh(pCol, 6.40) || isBitAgnosticIncompressibleHighEntropy(pCol, true) {
				return false
			}
			if len(pCol) < minEntropyBytes {
				if ent, _ := shannonEntropyAndPrintable(pCol); ent >= 6.00 && zlibCompressedRatio(pCol) >= 0.80 {
					return false
				}
			}
		}
	}
	return true
}

func isSmoothCLUT16(clut []byte, outC int) bool {
	stride := outC * 2
	if len(clut) < 256 || outC <= 0 || len(clut) <= stride+1 {
		return true
	}
	numPts := len(clut) / stride
	if numPts < 2 {
		return true
	}
	checkSeq16 := func(seq []uint16) bool {
		if len(seq) < 2 {
			return true
		}
		var sum uint64
		for i := 1; i < len(seq); i++ {
			d := int(seq[i]) - int(seq[i-1])
			if d < 0 {
				d = -d
			}
			sum += uint64(d)
		}
		return sum/uint64(len(seq)-1) < 16384
	}
	checkSeq16Windows := func(seq []uint16) bool {
		if !checkSeq16(seq) {
			return false
		}
		if len(seq)-1 >= 128 {
			win := min(256, max(64, len(seq)/4))
			step := max(1, win/2)
			for off := 0; off+win <= len(seq); off += step {
				if !checkSeq16(seq[off : off+win]) {
					return false
				}
			}
			if len(seq) > win && !checkSeq16(seq[len(seq)-win:]) {
				return false
			}
		}
		return true
	}
	checkSeq8 := func(seq []byte) bool {
		if len(seq) < 2 {
			return true
		}
		var sum uint64
		for i := 1; i < len(seq); i++ {
			d := int(seq[i]) - int(seq[i-1])
			if d < 0 {
				d = -d
			}
			sum += uint64(d)
		}
		return sum/uint64(len(seq)-1) < 55
	}
	checkSeq8Windows := func(seq []byte) bool {
		if !checkSeq8(seq) {
			return false
		}
		if len(seq)-1 >= 128 {
			win := min(256, max(64, len(seq)/4))
			step := max(1, win/2)
			for off := 0; off+win <= len(seq); off += step {
				if !checkSeq8(seq[off : off+win]) {
					return false
				}
			}
			if len(seq) > win && !checkSeq8(seq[len(seq)-win:]) {
				return false
			}
		}
		return true
	}
	ch := make([]uint16, numPts)
	nz := make([]uint16, 0, numPts)
	lo8 := make([]byte, numPts)
	nzLo8 := make([]byte, 0, numPts)
	for c := 0; c < outC; c++ {
		nz = nz[:0]
		nzLo8 = nzLo8[:0]
		var hiSeen [256]bool
		hiDistinct := 0
		counts16 := make(map[uint16]int, min(numPts, 256))
		bestVal16 := uint16(0)
		bestCnt16 := 0
		for i := 0; i < numPts; i++ {
			off := i*stride + c*2
			hi := clut[off]
			lo := clut[off+1]
			v := (uint16(hi) << 8) | uint16(lo)
			ch[i] = v
			lo8[i] = lo
			counts16[v]++
			if counts16[v] > bestCnt16 {
				bestCnt16 = counts16[v]
				bestVal16 = v
			}
			if v != 0 {
				nz = append(nz, v)
			}
			if lo != 0 {
				nzLo8 = append(nzLo8, lo)
			}
			if !hiSeen[hi] {
				hiSeen[hi] = true
				hiDistinct++
			}
		}
		if !checkSeq16Windows(ch) {
			return false
		}
		if len(nz) >= 128 && !checkSeq16Windows(nz) {
			return false
		}
		if bestCnt16*5 > numPts && numPts-bestCnt16 >= 128 {
			dom16 := make([]uint16, 0, numPts-bestCnt16)
			for _, v := range ch {
				if v != bestVal16 {
					dom16 = append(dom16, v)
				}
			}
			if !checkSeq16Windows(dom16) {
				return false
			}
		}
		type u16Count struct {
			val uint16
			cnt int
		}
		var cands16 []u16Count
		for v16, c16 := range counts16 {
			if c16*100 >= numPts*4 {
				cands16 = append(cands16, u16Count{val: v16, cnt: c16})
			}
		}
		if len(cands16) > 0 {
			sort.Slice(cands16, func(i, j int) bool {
				if cands16[i].cnt != cands16[j].cnt {
					return cands16[i].cnt > cands16[j].cnt
				}
				return cands16[i].val < cands16[j].val
			})
			if len(cands16) > 8 {
				cands16 = cands16[:8]
			}
			stripSet16 := make(map[uint16]struct{}, len(cands16))
			total16 := 0
			for _, cnd := range cands16 {
				stripSet16[cnd.val] = struct{}{}
				total16 += cnd.cnt
			}
			if total16*100 >= numPts*25 && numPts-total16 >= 128 {
				domTop16 := make([]uint16, 0, numPts-total16)
				for _, v := range ch {
					if _, drop := stripSet16[v]; !drop {
						domTop16 = append(domTop16, v)
					}
				}
				if !checkSeq16Windows(domTop16) {
					return false
				}
			}
		}
		if hiDistinct <= 4 && len(lo8) >= 128 {
			if !checkSeq8Windows(lo8) {
				return false
			}
			if len(nzLo8) >= 128 && !checkSeq8Windows(nzLo8) {
				return false
			}
			if domLo, ok := stripDominantByteIfOver(lo8, 20); ok && len(domLo) >= 128 && !checkSeq8Windows(domLo) {
				return false
			}
			if domLoK, ok := stripTopKBytes(lo8, 8, 4, 25); ok && len(domLoK) >= 128 && !checkSeq8Windows(domLoK) {
				return false
			}
			if nb, ok := stripNarrowBandBytes(lo8, 32, 0.40); ok && len(nb) >= minEntropyBytes {
				if hasConcealedHighEntropy(nb) {
					return false
				}
				if e, _ := shannonEntropyAndPrintable(nb); seqAvgDiff(nb) >= 55 && e >= 6.40 && zlibCompressedRatio(nb) >= 0.85 {
					return false
				}
			}
			if mp, ok := stripTopKMultiPad(lo8, 32, 0.40); ok && len(mp) >= minEntropyBytes {
				if e, _ := shannonEntropyAndPrintable(mp); seqAvgDiff(mp) >= 55 && e >= 6.40 && zlibCompressedRatio(mp) >= 0.85 {
					return false
				}
			}
			if pColLo := collapseRepeatedPeriodic(lo8, 32, 4); len(pColLo) >= 128 && len(pColLo) < len(lo8)*9/10 && !checkSeq8Windows(pColLo) {
				if hasConcealedHighEntropyThresh(pColLo, 6.40) || isBitAgnosticIncompressibleHighEntropy(pColLo, true) {
					return false
				}
				if len(pColLo) < minEntropyBytes {
					if ent, _ := shannonEntropyAndPrintable(pColLo); ent >= 6.00 && zlibCompressedRatio(pColLo) >= 0.80 {
						return false
					}
				}
			}
		}
	}
	return true
}

func isValidICCCurveOrPara(tagData []byte) (int, bool) {
	if len(tagData) < 12 {
		return 0, false
	}
	if tagData[4] != 0 || tagData[5] != 0 || tagData[6] != 0 || tagData[7] != 0 {
		return 0, false
	}
	sig := string(tagData[0:4])
	switch sig {
	case "curv":
		cnt := uint64(binary.BigEndian.Uint32(tagData[8:12]))
		if cnt > uint64(len(tagData)-12)/2 {
			return 0, false
		}
		rawLen := 12 + int(cnt)*2
		if cnt >= 2 && !isMonotonicUint16Slice(tagData[12:rawLen], int(cnt)) {
			return 0, false
		}
		padded := (rawLen + 3) &^ 3
		if padded > len(tagData) {
			padded = len(tagData)
		}
		return padded, true
	case "para":
		if len(tagData) < 16 {
			return 0, false
		}
		funcType := binary.BigEndian.Uint16(tagData[8:10])
		if funcType > 4 || binary.BigEndian.Uint16(tagData[10:12]) != 0 {
			return 0, false
		}
		sizes := [5]int{16, 24, 28, 32, 40}
		exp := sizes[funcType]
		if len(tagData) < exp {
			return 0, false
		}
		return exp, true
	default:
		return 0, false
	}
}

func isValidICCTagPayload(tagData []byte) bool {
	if len(tagData) < 8 {
		return false
	}
	if tagData[4] != 0 || tagData[5] != 0 || tagData[6] != 0 || tagData[7] != 0 {
		return false
	}
	typeSig := string(tagData[0:4])
	switch typeSig {
	case "curv":
		if len(tagData) < 12 {
			return false
		}
		cnt := uint64(binary.BigEndian.Uint32(tagData[8:12]))
		if cnt > uint64(len(tagData)-12)/2 {
			return false
		}
		exp := 12 + cnt*2
		if uint64(len(tagData))-exp > 3 {
			return false
		}
		if cnt >= 2 && !isMonotonicUint16Slice(tagData[12:exp], int(cnt)) {
			return false
		}
		return true
	case "para":
		if len(tagData) < 16 || len(tagData) > 43 {
			return false
		}
		funcType := binary.BigEndian.Uint16(tagData[8:10])
		if funcType > 4 || binary.BigEndian.Uint16(tagData[10:12]) != 0 {
			return false
		}
		sizes := [5]int{16, 24, 28, 32, 40}
		exp := sizes[funcType]
		return len(tagData) >= exp && len(tagData)-exp <= 3
	case "mft1":
		if len(tagData) < 48 || tagData[11] != 0 {
			return false
		}
		ic, oc, g := int(tagData[8]), int(tagData[9]), int(tagData[10])
		if ic < 1 || ic > 15 || oc < 1 || oc > 15 || g < 2 {
			return false
		}
		gPow := uint64(1)
		maxLimit := uint64(len(tagData))
		for k := 0; k < ic; k++ {
			if gPow > maxLimit/uint64(g) {
				return false
			}
			gPow *= uint64(g)
		}
		inBytes := uint64(ic) * 256
		clutBytes := gPow * uint64(oc)
		outBytes := uint64(oc) * 256
		if inBytes > maxLimit || clutBytes > maxLimit || outBytes > maxLimit {
			return false
		}
		exp := uint64(48) + inBytes + clutBytes + outBytes
		if exp > maxLimit || maxLimit-exp > 3 {
			return false
		}
		pos := 48
		for k := 0; k < ic; k++ {
			if !isMonotonicByteTable(tagData[pos : pos+256]) {
				return false
			}
			pos += 256
		}
		clutSlice := tagData[pos : pos+int(clutBytes)]
		pos += int(clutBytes)
		for k := 0; k < oc; k++ {
			if !isMonotonicByteTable(tagData[pos : pos+256]) {
				return false
			}
			pos += 256
		}
		if clutBytes >= 256 && !isSmoothCLUT8(clutSlice, oc) {
			return false
		}
		return true
	case "mft2":
		if len(tagData) < 52 || tagData[11] != 0 {
			return false
		}
		ic, oc, g := int(tagData[8]), int(tagData[9]), int(tagData[10])
		ie := int(binary.BigEndian.Uint16(tagData[48:50]))
		oe := int(binary.BigEndian.Uint16(tagData[50:52]))
		if ic < 1 || ic > 15 || oc < 1 || oc > 15 || g < 2 || ie < 2 || ie > 4096 || oe < 2 || oe > 4096 {
			return false
		}
		gPow := uint64(1)
		maxLimit := uint64(len(tagData))
		for k := 0; k < ic; k++ {
			if gPow > maxLimit/uint64(g) {
				return false
			}
			gPow *= uint64(g)
		}
		inBytes := uint64(ic) * uint64(ie) * 2
		clutBytes := gPow * uint64(oc) * 2
		outBytes := uint64(oc) * uint64(oe) * 2
		if inBytes > maxLimit || clutBytes > maxLimit || outBytes > maxLimit {
			return false
		}
		exp := uint64(52) + inBytes + clutBytes + outBytes
		if exp > maxLimit || maxLimit-exp > 3 {
			return false
		}
		pos := 52
		for k := 0; k < ic; k++ {
			if ie >= 16 && !isMonotonicUint16Slice(tagData[pos:pos+ie*2], ie) {
				return false
			}
			pos += ie * 2
		}
		clutSlice := tagData[pos : pos+int(clutBytes)]
		pos += int(clutBytes)
		for k := 0; k < oc; k++ {
			if oe >= 16 && !isMonotonicUint16Slice(tagData[pos:pos+oe*2], oe) {
				return false
			}
			pos += oe * 2
		}
		if clutBytes >= 256 && !isSmoothCLUT16(clutSlice, oc) {
			return false
		}
		return true
	case "mAB ", "mBA ":
		if len(tagData) < 32 || tagData[10] != 0 || tagData[11] != 0 {
			return false
		}
		ic, oc := int(tagData[8]), int(tagData[9])
		if ic < 1 || ic > 15 || oc < 1 || oc > 15 {
			return false
		}
		bOff := int(binary.BigEndian.Uint32(tagData[12:16]))
		matOff := int(binary.BigEndian.Uint32(tagData[16:20]))
		mOff := int(binary.BigEndian.Uint32(tagData[20:24]))
		clutOff := int(binary.BigEndian.Uint32(tagData[24:28]))
		aOff := int(binary.BigEndian.Uint32(tagData[28:32]))
		checkCurveChain := func(off, cnt int) (int, bool) {
			if off == 0 {
				return 0, true
			}
			if off < 32 || off >= len(tagData) || off%4 != 0 {
				return 0, false
			}
			cur := off
			for k := 0; k < cnt; k++ {
				if cur+12 > len(tagData) {
					return 0, false
				}
				step, ok := isValidICCCurveOrPara(tagData[cur:])
				if !ok || step <= 0 {
					return 0, false
				}
				cur += step
			}
			return cur, true
		}
		type mabSpan struct {
			start int
			end   int
		}
		var covered []mabSpan
		bEnd, bOK := checkCurveChain(bOff, oc)
		mEnd, mOK := checkCurveChain(mOff, oc)
		aEnd, aOK := checkCurveChain(aOff, ic)
		if !bOK || !mOK || !aOK {
			return false
		}
		if bOff != 0 {
			covered = append(covered, mabSpan{bOff, bEnd})
		}
		if mOff != 0 {
			covered = append(covered, mabSpan{mOff, mEnd})
		}
		if aOff != 0 {
			covered = append(covered, mabSpan{aOff, aEnd})
		}
		if matOff != 0 {
			if matOff < 32 || matOff%4 != 0 || matOff+48 > len(tagData) {
				return false
			}
			covered = append(covered, mabSpan{matOff, matOff + 48})
		}
		var clutBytes uint64
		if clutOff != 0 {
			if clutOff < 32 || clutOff%4 != 0 || clutOff+20 > len(tagData) {
				return false
			}
			prec := int(tagData[clutOff+16])
			if prec != 1 && prec != 2 {
				return false
			}
			prod := uint64(1)
			maxLimit := uint64(len(tagData) - clutOff - 20)
			for k := 0; k < ic; k++ {
				gp := int(tagData[clutOff+k])
				if gp < 2 {
					return false
				}
				if prod > maxLimit/uint64(gp) {
					return false
				}
				prod *= uint64(gp)
			}
			clutBytes = prod * uint64(oc) * uint64(prec)
			if clutBytes > maxLimit {
				return false
			}
			clutEnd := clutOff + 20 + int(clutBytes)
			covered = append(covered, mabSpan{clutOff, clutEnd})
			clutSlice := tagData[clutOff+20 : clutEnd]
			if clutBytes >= 256 {
				if prec == 1 && !isSmoothCLUT8(clutSlice, oc) {
					return false
				}
				if prec == 2 && !isSmoothCLUT16(clutSlice, oc) {
					return false
				}
			}
		}
		sort.Slice(covered, func(i, j int) bool {
			if covered[i].start != covered[j].start {
				return covered[i].start < covered[j].start
			}
			return covered[i].end < covered[j].end
		})
		curPos := 32
		gapTotal := 0
		maxCoveredEnd := 32
		for _, sp := range covered {
			if sp.start > curPos {
				gap := sp.start - curPos
				gapTotal += gap
				if gap >= minEntropyBytes {
					if _, highEnt := checkHighEntropy(tagData[curPos:sp.start]); highEnt {
						return false
					}
				}
			}
			if sp.end > curPos {
				curPos = sp.end
			}
			if sp.end > maxCoveredEnd {
				maxCoveredEnd = sp.end
			}
		}
		if len(tagData) > maxCoveredEnd {
			tailGap := len(tagData) - maxCoveredEnd
			gapTotal += tailGap
			if tailGap >= minEntropyBytes {
				if _, highEnt := checkHighEntropy(tagData[maxCoveredEnd:]); highEnt {
					return false
				}
			}
			if tailGap > 16 {
				return false
			}
		}
		if gapTotal > 20 {
			return false
		}
		if (clutOff == 0 || clutBytes < 256) && len(tagData)-32 >= minEntropyBytes {
			if _, highEnt := checkHighEntropy(tagData[32:]); highEnt {
				return false
			}
		}
		return true
	case "XYZ ":
		if len(tagData) < 20 || (len(tagData)-8)%12 != 0 {
			return false
		}
		return !hasConcealedHighEntropy(tagData)
	case "sig ":
		return len(tagData) >= 12 && len(tagData) <= 15
	case "view", "meas":
		return len(tagData) >= 36 && len(tagData) <= 39
	case "dtim":
		return len(tagData) >= 20 && len(tagData) <= 23
	case "mluc":
		if len(tagData) < 16 {
			return false
		}
		numRec := uint64(binary.BigEndian.Uint32(tagData[8:12]))
		recSize := binary.BigEndian.Uint32(tagData[12:16])
		if recSize != 12 || 16+numRec*12 > uint64(len(tagData)) {
			return false
		}
		return !hasConcealedHighEntropy(tagData)
	case "desc":
		if len(tagData) < 12 {
			return false
		}
		asciiLen := uint64(binary.BigEndian.Uint32(tagData[8:12]))
		if asciiLen > uint64(len(tagData)-12) {
			return false
		}
		return !hasConcealedHighEntropy(tagData)
	case "text", "data", "dict", "ZXML":
		return !hasConcealedHighEntropy(tagData)
	case "sf32", "uf32", "ui08", "ui16", "ui32", "ui64",
		"ncl2", "chrm", "vcgt", "pseq", "clro", "clrt", "clot",
		"psid", "rcs2", "resp", "scrn", "ucbg", "chad",
		"cicp", "svcn", "gbd ", "mpet", "bfd ":
		return !hasConcealedHighEntropy(tagData)
	default:
		return false
	}
}

func isValidICCProfileHeaderAndTags(b []byte) bool {
	if len(b) < 132 {
		return false
	}
	if string(b[36:40]) != "acsp" {
		return false
	}
	profileSize := binary.BigEndian.Uint32(b[0:4])
	if uint64(profileSize) < 132 || uint64(profileSize) > uint64(len(b)) {
		return false
	}
	if len(b)-int(profileSize) > 16 {
		return false
	}
	majorVer := b[8]
	if majorVer < 2 || majorVer > 5 {
		return false
	}
	profClass := string(b[12:16])
	switch profClass {
	case "scnr", "mntr", "prtr", "link", "spac", "abst", "nmcl":
	default:
		return false
	}
	if !isValidICCColorSpace(string(b[16:20])) {
		return false
	}
	pcs := string(b[20:24])
	if pcs != "XYZ " && pcs != "Lab " && !(profClass == "link" && isValidICCColorSpace(pcs)) {
		return false
	}
	tagCount := binary.BigEndian.Uint32(b[128:132])
	if tagCount < 3 || tagCount > 512 {
		return false
	}
	tableEnd := uint64(132) + uint64(tagCount)*12
	if tableEnd > uint64(profileSize) {
		return false
	}
	type tagSpan struct {
		start uint64
		end   uint64
	}
	spans := make([]tagSpan, 0, tagCount)
	for i := uint32(0); i < tagCount; i++ {
		off := 132 + int(i)*12
		for j := 0; j < 4; j++ {
			c := b[off+j]
			if c < 0x20 || c > 0x7e {
				return false
			}
		}
		tagOff := uint64(binary.BigEndian.Uint32(b[off+4 : off+8]))
		tagSize := uint64(binary.BigEndian.Uint32(b[off+8 : off+12]))
		if tagOff%4 != 0 || tagSize < 8 || tagOff < tableEnd || tagOff+tagSize > uint64(profileSize) {
			return false
		}
		if !isValidICCTagPayload(b[tagOff : tagOff+tagSize]) {
			return false
		}
		spans = append(spans, tagSpan{start: tagOff, end: tagOff + tagSize})
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	gapTotal := uint64(0)
	cur := tableEnd
	for _, sp := range spans {
		if sp.start > cur {
			gap := sp.start - cur
			gapTotal += gap
			if gap >= minEntropyBytes {
				if _, highEnt := checkHighEntropy(b[cur:sp.start]); highEnt {
					return false
				}
			}
		}
		if sp.end > cur {
			cur = sp.end
		}
	}
	if uint64(profileSize) > cur {
		tailGap := uint64(profileSize) - cur
		gapTotal += tailGap
		if tailGap >= minEntropyBytes {
			if _, highEnt := checkHighEntropy(b[cur:profileSize]); highEnt {
				return false
			}
		}
	}
	return gapTotal <= uint64(tagCount)*4+16
}

func inspectValidatedICCProfile(
	ctx context.Context,
	virtualPath string,
	suffix string,
	iccData []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	stripped := stripControlBytesForInspection(iccData)
	emitCredentialFindings(virtualPath, iccData, res)
	if len(stripped) > 0 && len(stripped) != len(iccData) {
		emitCredentialFindings(virtualPath, stripped, res)
	}
	if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
		subPath := virtualPath + suffix
		res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
			VirtualPath:    subPath,
			Data:           extracted,
			InArchive:      inArchive,
			InEncoded:      inEncoded,
			ExtractedMedia: true,
		})
		emitCredentialFindings(subPath, extracted, res)
		if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
			inspectEncodedPayloads(ctx, subPath, extracted, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
		}
	}
}

func findEmbeddedJPEGEnd(b []byte) int {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 || b[2] != 0xFF {
		return -1
	}
	off := 2
	inScan := false
	for off+1 < len(b) {
		if !inScan {
			for off+1 < len(b) && b[off] == 0xFF && b[off+1] == 0xFF {
				off++
			}
			if off+1 >= len(b) || b[off] != 0xFF {
				return -1
			}
			m := b[off+1]
			if m == 0xD9 {
				return off + 2
			}
			if m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
				off += 2
				continue
			}
			if off+4 > len(b) {
				return -1
			}
			segLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
			if segLen < 2 || off+2+segLen > len(b) {
				return -1
			}
			off += 2 + segLen
			if m == 0xDA {
				inScan = true
			}
			continue
		}
		if b[off] != 0xFF {
			off++
			continue
		}
		next := b[off+1]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			off += 2
			continue
		}
		if next == 0xFF {
			off++
			continue
		}
		if next == 0xD9 {
			return off + 2
		}
		if off+4 > len(b) {
			return -1
		}
		segLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if segLen < 2 || off+2+segLen > len(b) {
			return -1
		}
		off += 2 + segLen
	}
	return -1
}

func inspectExifPayload(
	ctx context.Context,
	virtualPath string,
	suffix string,
	payload []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	isExifHeader := bytes.HasPrefix(payload, []byte("Exif\x00\x00")) ||
		bytes.HasPrefix(payload, []byte("II*\x00")) ||
		bytes.HasPrefix(payload, []byte("MM\x00*"))
	if isExifHeader {
		if soi := bytes.Index(payload, []byte{0xFF, 0xD8, 0xFF}); soi >= 0 {
			if eoiRel := findEmbeddedJPEGEnd(payload[soi:]); eoiRel > 0 {
				thumb := payload[soi : soi+eoiRel]
				if isValidJPEGStructure(thumb) {
					inspectJPEGMetadataSegments(ctx, virtualPath+suffix+"#thumb", thumb, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					remaining := make([]byte, 0, len(payload)-len(thumb))
					remaining = append(remaining, payload[:soi]...)
					remaining = append(remaining, payload[soi+eoiRel:]...)
					inspectAncillaryPayload(ctx, virtualPath, suffix, remaining, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					return
				}
			}
		}
	}
	inspectAncillaryPayload(ctx, virtualPath, suffix, payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
}

func inspectAncillaryPayload(
	ctx context.Context,
	virtualPath string,
	suffix string,
	payload []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if len(payload) == 0 {
		return
	}
	if ent, flagged := checkHighEntropy(payload); flagged {
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.high-entropy",
			domain.SeverityHigh,
			virtualPath,
			"high-entropy payload inside media metadata or ancillary chunk",
			map[string]any{
				"layer":         "L4_CONCEALMENT",
				"technique":     "high_entropy",
				"chunk_suffix":  suffix,
				"shannon_bits":  math.Round(ent*1000) / 1000,
				"payload_bytes": len(payload),
			},
			fmt.Sprintf("ancillary_entropy:%s:%.3f:%d", suffix, ent, len(payload)),
		))
	}
	stripped := stripControlBytesForInspection(payload)
	if len(stripped) >= minEntropyBytes && len(stripped) < len(payload)*9/10 {
		if ent, flagged := checkHighEntropy(stripped); flagged {
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.high-entropy",
				domain.SeverityHigh,
				virtualPath,
				"high-entropy C0-diluted payload inside media metadata or ancillary chunk",
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "high_entropy",
					"chunk_suffix":  suffix,
					"shannon_bits":  math.Round(ent*1000) / 1000,
					"payload_bytes": len(stripped),
				},
				fmt.Sprintf("ancillary_stripped_entropy:%s:%.3f:%d", suffix, ent, len(stripped)),
			))
		}
	}
	emitCredentialFindings(virtualPath, payload, res)
	if len(stripped) > 0 && len(stripped) != len(payload) {
		emitCredentialFindings(virtualPath, stripped, res)
	}
	if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
		subPath := virtualPath + suffix
		res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
			VirtualPath:    subPath,
			Data:           extracted,
			InArchive:      inArchive,
			InEncoded:      inEncoded,
			ExtractedMedia: true,
		})
		emitCredentialFindings(subPath, extracted, res)
		if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
			inspectEncodedPayloads(ctx, subPath, extracted, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
		}
	}
}

func isJPEGSOFMarker(m byte) bool {
	return (m >= 0xC0 && m <= 0xC3) ||
		(m >= 0xC5 && m <= 0xC7) ||
		(m >= 0xC9 && m <= 0xCB) ||
		(m >= 0xCD && m <= 0xCF)
}

func isJPEGProbablyHuffmanSOF(m byte) bool {
	return m == 0xC0 || m == 0xC1 || m == 0xC2 || m == 0xC3 || m == 0xC5 || m == 0xC6 || m == 0xC7
}

func isValidDQTSegment(segPayload []byte) bool {
	return validDQTSegmentTables(segPayload) > 0
}

func hasRawOrC0HighEntropy(b []byte) bool {
	if _, highEnt := checkHighEntropy(b); highEnt {
		return true
	}
	stripped := stripControlBytesForInspection(b)
	if len(stripped) >= minEntropyBytes && len(stripped) < len(b)*9/10 {
		if _, highEnt := checkHighEntropy(stripped); highEnt {
			return true
		}
	}
	return false
}

func hasConcealedHighEntropy(b []byte) bool {
	return hasConcealedHighEntropyThresh(b, entropyThreshold)
}

func checkMaxEntWindowIncompressible(data []byte, thresh float64) bool {
	if len(data) < minEntropyBytes {
		return false
	}
	highPrintableThresh := max(thresh, entropyThresholdHighPrintable)
	checkWin := func(win []byte) bool {
		ent, printableRatio := shannonEntropyAndPrintable(win)
		if ent >= thresh && (printableRatio < 0.85 || ent >= highPrintableThresh) {
			return zlibCompressedRatio(win) >= 0.88
		}
		return false
	}
	if len(data) <= 1<<20 && checkWin(data) {
		return true
	}
	if len(data) > entropyWindowBytes {
		step := entropyWindowStep
		if span := len(data) - entropyWindowBytes; span/step+1 > entropyMaxWindows {
			step = max(span/entropyMaxWindows, entropyWindowStep)
		}
		lastOff := -1
		for off := 0; off+entropyWindowBytes <= len(data); off += step {
			lastOff = off
			if checkWin(data[off : off+entropyWindowBytes]) {
				return true
			}
		}
		tailOff := len(data) - entropyWindowBytes
		if tailOff > lastOff && checkWin(data[tailOff:]) {
			return true
		}
	}
	return false
}

func hasConcealedHighEntropyThresh(b []byte, thresh float64) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	if _, highEnt := checkHighEntropyThresh(b, thresh); highEnt {
		return true
	}
	stripped := stripControlBytesForInspection(b)
	if len(stripped) >= minEntropyBytes && len(stripped) < len(b)*9/10 {
		if _, highEnt := checkHighEntropyThresh(stripped, thresh); highEnt {
			return true
		}
	}
	collapsed := collapseRepeatedBytes(b, 16)
	if len(collapsed) >= minEntropyBytes && len(collapsed) < len(b)*9/10 {
		if _, highEnt := checkHighEntropyThresh(collapsed, thresh); highEnt {
			return true
		}
		if cStrip := stripControlBytesForInspection(collapsed); len(cStrip) >= minEntropyBytes && len(cStrip) < len(collapsed)*9/10 {
			if _, highEnt := checkHighEntropyThresh(cStrip, thresh); highEnt {
				return true
			}
		}
	}
	pCollapsed := collapseRepeatedPeriodic(b, 32, 4)
	if len(pCollapsed) >= minEntropyBytes && len(pCollapsed) < len(b)*9/10 {
		if checkMaxEntWindowIncompressible(pCollapsed, thresh) {
			return true
		}
		if thresh <= 7.25 && isBitAgnosticIncompressibleHighEntropy(pCollapsed, true) {
			return true
		}
		if pStrip := stripControlBytesForInspection(pCollapsed); len(pStrip) >= minEntropyBytes && len(pStrip) < len(pCollapsed)*9/10 {
			if checkMaxEntWindowIncompressible(pStrip, thresh) {
				return true
			}
		}
	}
	if hasConstantLanePlusHighEntResidualThresh(b, thresh) {
		return true
	}
	if dom, ok := stripDominantByteIfOver(b, 20); ok && len(dom) >= minEntropyBytes {
		if checkMaxEntWindowIncompressible(dom, thresh) {
			return true
		}
		if thresh <= 7.25 && isBitAgnosticIncompressibleHighEntropy(dom, true) {
			return true
		}
	}
	if thresh <= 7.25 {
		if isBitAgnosticIncompressibleHighEntropy(b, true) {
			return true
		}
		if isTopKPadDilutedHighEntropy(b, true) {
			return true
		}
	}
	return false
}

func dqtTableStats(tbl []byte) (adjDiff float64, distinct int, ent float64) {
	if len(tbl) == 0 {
		return 0, 0, 0
	}
	var seen [256]bool
	var sumDiff int
	for i := 0; i < len(tbl); i++ {
		if !seen[tbl[i]] {
			seen[tbl[i]] = true
			distinct++
		}
		if i > 0 {
			d := int(tbl[i]) - int(tbl[i-1])
			if d < 0 {
				d = -d
			}
			sumDiff += d
		}
	}
	if len(tbl) > 1 {
		adjDiff = float64(sumDiff) / float64(len(tbl)-1)
	}
	ent, _ = shannonEntropyAndPrintable(tbl)
	return adjDiff, distinct, ent
}

func distinctUint16Count(tbl []byte) int {
	if len(tbl) < 2 {
		return 0
	}
	seen := make(map[uint16]struct{}, len(tbl)/2)
	for i := 0; i+1 < len(tbl); i += 2 {
		seen[binary.BigEndian.Uint16(tbl[i:i+2])] = struct{}{}
	}
	return len(seen)
}

func stripModalDQTResidual(tbl []byte) []byte {
	if len(tbl) == 0 {
		return nil
	}
	var cnt [256]int
	for _, x := range tbl {
		cnt[x]++
	}
	bestByte := byte(0)
	bestCnt := 0
	for i, c := range cnt {
		if c > bestCnt {
			bestCnt = c
			bestByte = byte(i)
		}
	}
	if bestCnt*4 <= len(tbl) {
		return tbl
	}
	out := make([]byte, 0, len(tbl)-bestCnt)
	for _, x := range tbl {
		if x != bestByte {
			out = append(out, x)
		}
	}
	return out
}

func extractNonTrivialDQTTables(segPayload []byte) ([]byte, int) {
	if len(segPayload) < 65 || len(segPayload) > 4*129 {
		return nil, 0
	}
	var seenTq [4]bool
	var nonTrivial []byte
	off := 0
	tables := 0
	for off < len(segPayload) {
		pqTq := segPayload[off]
		off++
		pq := pqTq >> 4
		tq := pqTq & 0x0f
		if pq > 1 || tq > 3 || seenTq[tq] {
			return nil, 0
		}
		seenTq[tq] = true
		tableBytes := 64 * (1 + int(pq))
		if off+tableBytes > len(segPayload) {
			return nil, 0
		}
		tbl := segPayload[off : off+tableBytes]
		if pq == 0 {
			adjDiff, distinct, ent := dqtTableStats(tbl)
			if adjDiff > 52 && distinct >= 48 && ent >= 5.50 {
				return nil, 0
			}
			res := stripModalDQTResidual(tbl)
			if len(res) >= 24 {
				rAdj, rDist, rEnt := dqtTableStats(res)
				if rAdj > 52 && rDist >= 24 && rEnt >= 4.70 {
					return nil, 0
				}
			}
			if len(res) >= 16 {
				nonTrivial = append(nonTrivial, res...)
			} else if distinct > 8 && ent >= 3.5 {
				nonTrivial = append(nonTrivial, tbl...)
			}
		} else {
			gt4096 := 0
			var lo64 [64]byte
			for k := 0; k < 64; k++ {
				if binary.BigEndian.Uint16(tbl[k*2:k*2+2]) > 4096 {
					gt4096++
				}
				lo64[k] = tbl[k*2+1]
			}
			if gt4096 > 16 {
				return nil, 0
			}
			adjDiff, distinctLo, entLo := dqtTableStats(lo64[:])
			if adjDiff > 52 && distinctLo >= 48 && entLo >= 5.50 {
				return nil, 0
			}
			resLo := stripModalDQTResidual(lo64[:])
			if len(resLo) >= 24 {
				rAdj, rDist, rEnt := dqtTableStats(resLo)
				if rAdj > 52 && rDist >= 24 && rEnt >= 4.70 {
					return nil, 0
				}
			}
			_, distinct, ent := dqtTableStats(tbl)
			if len(resLo) >= 16 {
				nonTrivial = append(nonTrivial, resLo...)
			} else if distinct > 8 && distinctUint16Count(tbl) > 8 && ent >= 3.5 {
				nonTrivial = append(nonTrivial, tbl...)
			}
		}
		off += tableBytes
		tables++
	}
	if tables == 0 || tables > 4 || off != len(segPayload) {
		return nil, 0
	}
	return nonTrivial, tables
}

func allSameByteSlice(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	first := b[0]
	for i := 1; i < len(b); i++ {
		if b[i] != first {
			return false
		}
	}
	return true
}

func validDQTSegmentTables(segPayload []byte) int {
	nonTrivial, tables := extractNonTrivialDQTTables(segPayload)
	if tables == 0 {
		return 0
	}
	if len(nonTrivial) >= minEntropyBytes && hasConcealedHighEntropy(nonTrivial) {
		return 0
	}
	if inferLanguageFromContent(segPayload) != "" {
		return 0
	}
	stripped := stripControlBytesForInspection(segPayload)
	if len(stripped) != len(segPayload) && inferLanguageFromContent(stripped) != "" {
		return 0
	}
	return tables
}

func isValidDHTSegment(segPayload []byte) bool {
	return validDHTSegmentTables(segPayload) > 0
}

func validDHTSegmentTables(segPayload []byte) int {
	if len(segPayload) < 17 || len(segPayload) > 8*(1+16+256) {
		return 0
	}
	var seenTcTh [2][4]bool
	off := 0
	tables := 0
	for off < len(segPayload) {
		if off+17 > len(segPayload) {
			return 0
		}
		tcTh := segPayload[off]
		off++
		tc := tcTh >> 4
		th := tcTh & 0x0f
		if tc > 1 || th > 3 || seenTcTh[tc][th] {
			return 0
		}
		seenTcTh[tc][th] = true
		totalSyms := 0
		kraft := 0
		for i := 0; i < 16; i++ {
			cnt := int(segPayload[off+i])
			totalSyms += cnt
			kraft += cnt << (15 - i)
		}
		off += 16
		if totalSyms > 256 || kraft > (1<<16) || off+totalSyms > len(segPayload) {
			return 0
		}
		var seenSym [256]bool
		for i := 0; i < totalSyms; i++ {
			sym := segPayload[off+i]
			if seenSym[sym] {
				return 0
			}
			seenSym[sym] = true
		}
		off += totalSyms
		tables++
	}
	if tables == 0 || tables > 8 || off != len(segPayload) {
		return 0
	}
	if inferLanguageFromContent(segPayload) != "" {
		return 0
	}
	stripped := stripControlBytesForInspection(segPayload)
	if len(stripped) != len(segPayload) && inferLanguageFromContent(stripped) != "" {
		return 0
	}
	return tables
}

type jpegScanSpan struct {
	start int
	end   int
}

func tryDecodeJPEGWithoutTail(data []byte, spanStart, spanEnd, trimBytes int) bool {
	if spanEnd-spanStart < trimBytes {
		return false
	}
	cut := spanEnd - trimBytes
	if cut > spanStart && data[cut-1] == 0xFF {
		cut--
	}
	if cut <= spanStart {
		return false
	}
	trunc := make([]byte, 0, len(data)-(spanEnd-cut))
	trunc = append(trunc, data[:cut]...)
	trunc = append(trunc, data[spanEnd:]...)
	_, err := jpeg.Decode(bytes.NewReader(trunc))
	return err == nil
}

type jpegCutSpan struct {
	cut int
	end int
}

type jpegHuffTable struct {
	nCodes      int32
	lut         [256]uint16
	vals        [256]uint8
	minCodes    [16]int32
	maxCodes    [16]int32
	valsIndices [16]int32
}

type jpegBitReader struct {
	buf      []byte
	pos      int
	a        uint32
	n        int32
	m        uint32
	byteLens [8]uint8
	byteTail int
}

func (br *jpegBitReader) reset(buf []byte) {
	br.buf = buf
	br.pos = 0
	br.a = 0
	br.n = 0
	br.m = 0
	br.byteTail = 0
}

func (br *jpegBitReader) readByteStuffed() (byte, bool) {
	if br.pos >= len(br.buf) {
		return 0, false
	}
	x := br.buf[br.pos]
	if x != 0xFF {
		br.pos++
		br.byteLens[br.byteTail&7] = 1
		br.byteTail++
		return x, true
	}
	if br.pos+1 >= len(br.buf) || br.buf[br.pos+1] != 0x00 {
		return 0, false
	}
	br.pos += 2
	br.byteLens[br.byteTail&7] = 2
	br.byteTail++
	return 0xFF, true
}

func (br *jpegBitReader) ensureNBits(need int32) bool {
	for br.n < need {
		c, ok := br.readByteStuffed()
		if !ok {
			return false
		}
		br.a = br.a<<8 | uint32(c)
		br.n += 8
		if br.m == 0 {
			br.m = 1 << 7
		} else {
			br.m <<= 8
		}
	}
	return true
}

func (br *jpegBitReader) decodeHuffman(h *jpegHuffTable) (uint8, bool) {
	if h.nCodes == 0 {
		return 0, false
	}
	if br.n < 8 {
		_ = br.ensureNBits(8)
	}
	if br.n >= 8 {
		if v := h.lut[(br.a>>uint32(br.n-8))&0xff]; v != 0 {
			nBits := (v & 0xff) - 1
			br.n -= int32(nBits)
			br.m >>= nBits
			return uint8(v >> 8), true
		}
	}
	var code int32
	for i := 0; i < 16; i++ {
		if br.n == 0 {
			if !br.ensureNBits(1) {
				return 0, false
			}
		}
		if br.a&br.m != 0 {
			code |= 1
		}
		br.n--
		br.m >>= 1
		if code <= h.maxCodes[i] {
			idx := h.valsIndices[i] + code - h.minCodes[i]
			if idx < 0 || idx >= h.nCodes {
				return 0, false
			}
			return h.vals[idx], true
		}
		code <<= 1
	}
	return 0, false
}

func (br *jpegBitReader) decodeBits(nb int32) (uint32, bool) {
	if nb == 0 {
		return 0, true
	}
	if br.n < nb {
		if !br.ensureNBits(nb) {
			return 0, false
		}
	}
	ret := br.a >> uint32(br.n-nb)
	ret &= (1 << uint32(nb)) - 1
	br.n -= nb
	br.m >>= uint(nb)
	return ret, true
}

func (br *jpegBitReader) decodeBit() (bool, bool) {
	if br.n == 0 {
		if !br.ensureNBits(1) {
			return false, false
		}
	}
	ret := br.a&br.m != 0
	br.n--
	br.m >>= 1
	return ret, true
}

func (br *jpegBitReader) consumedPos() int {
	consumed := br.pos
	unused := int(br.n / 8)
	for k := 0; k < unused && k < 8 && br.byteTail > 0; k++ {
		br.byteTail--
		consumed -= int(br.byteLens[br.byteTail&7])
	}
	if consumed < 0 {
		return 0
	}
	return consumed
}

func findJPEGUnusedRSTSpans(data []byte) ([]jpegCutSpan, int, bool) {
	if len(data) < 16 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, 0, false
	}
	var (
		huff       [2][4]jpegHuffTable
		sofMarker  byte
		sofW, sofH int
		nComp      int
		comps      [4]struct {
			c byte
			h int
			v int
		}
		maxH, maxV  int
		driVal      int
		progNonZero [4][]uint64
		cuts        []jpegCutSpan
		totalTrim   int
	)
	off := 2
	for off+1 < len(data) {
		for off+1 < len(data) && data[off] == 0xFF && data[off+1] == 0xFF {
			off++
		}
		if off+1 >= len(data) || data[off] != 0xFF {
			return nil, 0, false
		}
		m := data[off+1]
		if m == 0xD9 {
			break
		}
		if m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			off += 2
			continue
		}
		if off+4 > len(data) {
			return nil, 0, false
		}
		segLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if segLen < 2 || off+2+segLen > len(data) {
			return nil, 0, false
		}
		segPayload := data[off+4 : off+2+segLen]
		switch {
		case m == 0xDD:
			if segLen != 4 {
				return nil, 0, false
			}
			driVal = int(binary.BigEndian.Uint16(segPayload[0:2]))
		case m == 0xC4:
			p := 0
			for p < len(segPayload) {
				if p+17 > len(segPayload) {
					return nil, 0, false
				}
				tc := int(segPayload[p] >> 4)
				th := int(segPayload[p] & 0x0f)
				if tc > 1 || th > 3 {
					return nil, 0, false
				}
				h := &huff[tc][th]
				*h = jpegHuffTable{}
				var nCodes [16]int32
				for i := 0; i < 16; i++ {
					nCodes[i] = int32(segPayload[p+1+i])
					h.nCodes += nCodes[i]
				}
				if h.nCodes == 0 || h.nCodes > 256 || p+17+int(h.nCodes) > len(segPayload) {
					return nil, 0, false
				}
				copy(h.vals[:h.nCodes], segPayload[p+17:p+17+int(h.nCodes)])
				var x, code uint32
				for i := uint32(0); i < 8; i++ {
					code <<= 1
					for j := int32(0); j < nCodes[i]; j++ {
						base := uint8(code << (7 - i))
						lutVal := uint16(h.vals[x])<<8 | uint16(2+i)
						for k := uint8(0); k < 1<<(7-i); k++ {
							h.lut[base|k] = lutVal
						}
						code++
						x++
					}
				}
				var cVal, index int32
				for i, nc := range nCodes {
					if nc == 0 {
						h.minCodes[i] = -1
						h.maxCodes[i] = -1
						h.valsIndices[i] = -1
					} else {
						h.minCodes[i] = cVal
						h.maxCodes[i] = cVal + nc - 1
						h.valsIndices[i] = index
						cVal += nc
						index += nc
					}
					cVal <<= 1
				}
				p += 17 + int(h.nCodes)
			}
		case m == 0xC0 || m == 0xC1 || m == 0xC2:
			if segLen < 8 {
				return nil, 0, false
			}
			sofMarker = m
			sofH = int(binary.BigEndian.Uint16(segPayload[1:3]))
			sofW = int(binary.BigEndian.Uint16(segPayload[3:5]))
			nComp = int(segPayload[5])
			if nComp < 1 || nComp > 4 || segLen != 8+3*nComp || sofW == 0 || sofH == 0 {
				return nil, 0, false
			}
			maxH, maxV = 0, 0
			for i := 0; i < nComp; i++ {
				comps[i].c = segPayload[6+3*i]
				hv := segPayload[6+3*i+1]
				comps[i].h = int(hv >> 4)
				comps[i].v = int(hv & 0x0f)
				if comps[i].h == 0 || comps[i].v == 0 {
					return nil, 0, false
				}
				if comps[i].h > maxH {
					maxH = comps[i].h
				}
				if comps[i].v > maxV {
					maxV = comps[i].v
				}
			}
		case m == 0xDA:
			if (sofMarker != 0xC0 && sofMarker != 0xC1 && sofMarker != 0xC2) || nComp == 0 {
				return nil, 0, false
			}
			ns := int(segPayload[0])
			if ns < 1 || ns > nComp || len(segPayload) != 4+2*ns {
				return nil, 0, false
			}
			var scan [4]struct {
				compIdx int
				td      int
				ta      int
			}
			for i := 0; i < ns; i++ {
				cs := segPayload[1+2*i]
				cIdx := -1
				for j := 0; j < nComp; j++ {
					if comps[j].c == cs {
						cIdx = j
						break
					}
				}
				if cIdx < 0 {
					return nil, 0, false
				}
				scan[i].compIdx = cIdx
				scan[i].td = int(segPayload[2+2*i] >> 4)
				scan[i].ta = int(segPayload[2+2*i] & 0x0f)
				if scan[i].td > 3 || scan[i].ta > 3 {
					return nil, 0, false
				}
			}
			zigStart, zigEnd, ah := 0, 63, 0
			if sofMarker == 0xC2 {
				zigStart = int(segPayload[1+2*ns])
				zigEnd = int(segPayload[2+2*ns])
				ah = int(segPayload[3+2*ns] >> 4)
				if zigStart > zigEnd || zigEnd >= 64 {
					return nil, 0, false
				}
			}
			mxx := (sofW + 8*maxH - 1) / (8 * maxH)
			myy := (sofH + 8*maxV - 1) / (8 * maxV)
			if sofMarker == 0xC2 {
				for i := 0; i < ns; i++ {
					ci := scan[i].compIdx
					if progNonZero[ci] == nil {
						blkTotal := mxx * myy * comps[ci].h * comps[ci].v
						if blkTotal <= 0 || blkTotal > 4_000_000 {
							return nil, 0, false
						}
						progNonZero[ci] = make([]uint64, blkTotal)
					}
				}
			}

			scanBodyStart := off + 2 + segLen
			var ivs []jpegScanSpan
			ivS := scanBodyStart
			p := scanBodyStart
			scanEnd := -1
			for p < len(data) {
				if data[p] != 0xFF {
					p++
					continue
				}
				if p+1 >= len(data) {
					return nil, 0, false
				}
				nm := data[p+1]
				if nm == 0x00 {
					p += 2
					continue
				}
				if nm == 0xFF {
					p++
					continue
				}
				if nm >= 0xD0 && nm <= 0xD7 {
					ivs = append(ivs, jpegScanSpan{start: ivS, end: p})
					p += 2
					ivS = p
					continue
				}
				ivs = append(ivs, jpegScanSpan{start: ivS, end: p})
				scanEnd = p
				break
			}
			if scanEnd < 0 || len(ivs) == 0 {
				return nil, 0, false
			}
			if driVal == 0 && len(ivs) > 1 {
				return nil, 0, false
			}

			ivIdx := 0
			var br jpegBitReader
			br.reset(data[ivs[0].start:ivs[0].end])
			mcu := 0
			totalMCUs := mxx * myy
			if ns == 1 {
				ci0 := scan[0].compIdx
				bw := (sofW*comps[ci0].h + 8*maxH - 1) / (8 * maxH)
				bh := (sofH*comps[ci0].v + 8*maxV - 1) / (8 * maxV)
				totalMCUs = bw * bh
			}
			blockCount := 0
			eobRun := uint16(0)

			advanceMCU := func() bool {
				mcu++
				if driVal > 0 && mcu%driVal == 0 && mcu < totalMCUs {
					consumed := br.consumedPos()
					curIv := ivs[ivIdx]
					if consumed > 0 && curIv.start+consumed < curIv.end {
						cut := curIv.start + consumed
						if cut > curIv.start && data[cut-1] == 0xFF {
							cut--
						}
						if cut > curIv.start {
							cuts = append(cuts, jpegCutSpan{cut: cut, end: curIv.end})
							totalTrim += curIv.end - cut
						}
					}
					ivIdx++
					if ivIdx >= len(ivs) {
						return false
					}
					br.reset(data[ivs[ivIdx].start:ivs[ivIdx].end])
					eobRun = 0
				}
				return true
			}

			refineNonZeroes := func(nzMask *uint64, zig, nz int) (int, bool) {
				for ; zig <= zigEnd; zig++ {
					if ((*nzMask) & (uint64(1) << uint(zig))) == 0 {
						if nz == 0 {
							break
						}
						nz--
						continue
					}
					if _, ok := br.decodeBit(); !ok {
						return 0, false
					}
				}
				return zig, true
			}

			for my := 0; my < myy; my++ {
				for mx := 0; mx < mxx; mx++ {
					for i := 0; i < ns; i++ {
						ci := scan[i].compIdx
						hi := comps[ci].h
						vi := comps[ci].v
						for j := 0; j < hi*vi; j++ {
							var bx, by int
							if ns != 1 {
								bx = hi*mx + j%hi
								by = vi*my + j/hi
							} else {
								q := mxx * hi
								bx = blockCount % q
								by = blockCount / q
								blockCount++
								if bx*8*maxH >= sofW*hi || by*8*maxV >= sofH*vi {
									continue
								}
							}
							var nzMask *uint64
							if sofMarker == 0xC2 {
								idx := by*mxx*hi + bx
								if idx < 0 || idx >= len(progNonZero[ci]) {
									return nil, 0, false
								}
								nzMask = &progNonZero[ci][idx]
							}
							if ah != 0 {
								if zigStart == 0 {
									if _, ok := br.decodeBit(); !ok {
										return nil, 0, false
									}
								} else {
									zig := zigStart
									if eobRun == 0 {
										hAC := &huff[1][scan[i].ta]
										for ; zig <= zigEnd; zig++ {
											zNonZero := false
											val, ok := br.decodeHuffman(hAC)
											if !ok {
												return nil, 0, false
											}
											val0 := int(val >> 4)
											val1 := int(val & 0x0f)
											if val1 == 0 {
												if val0 != 0x0f {
													eobRun = uint16(1 << uint(val0))
													if val0 != 0 {
														eb, eOK := br.decodeBits(int32(val0))
														if !eOK {
															return nil, 0, false
														}
														eobRun |= uint16(eb)
													}
													break
												}
											} else if val1 == 1 {
												if _, bOK := br.decodeBit(); !bOK {
													return nil, 0, false
												}
												zNonZero = true
											} else {
												return nil, 0, false
											}
											newZig, rOK := refineNonZeroes(nzMask, zig, val0)
											if !rOK || newZig > zigEnd {
												return nil, 0, false
											}
											zig = newZig
											if zNonZero {
												*nzMask |= uint64(1) << uint(zig)
											}
										}
									}
									if eobRun > 0 {
										eobRun--
										if _, rOK := refineNonZeroes(nzMask, zig, -1); !rOK {
											return nil, 0, false
										}
									}
								}
							} else {
								zig := zigStart
								if zig == 0 {
									zig++
									val, ok := br.decodeHuffman(&huff[0][scan[i].td])
									if !ok || val > 16 {
										return nil, 0, false
									}
									if _, ok := br.decodeBits(int32(val)); !ok {
										return nil, 0, false
									}
								}
								if zig <= zigEnd && eobRun > 0 {
									eobRun--
								} else if zig <= zigEnd {
									hAC := &huff[1][scan[i].ta]
									for ; zig <= zigEnd; zig++ {
										val, ok := br.decodeHuffman(hAC)
										if !ok {
											return nil, 0, false
										}
										val0 := int(val >> 4)
										val1 := int(val & 0x0f)
										if val1 != 0 {
											zig += val0
											if zig > zigEnd {
												break
											}
											if _, ok := br.decodeBits(int32(val1)); !ok {
												return nil, 0, false
											}
											if nzMask != nil {
												*nzMask |= uint64(1) << uint(zig)
											}
										} else {
											if val0 != 0x0f {
												eobRun = uint16(1 << uint(val0))
												if val0 != 0 {
													eb, eOK := br.decodeBits(int32(val0))
													if !eOK {
														return nil, 0, false
													}
													eobRun |= uint16(eb)
												}
												eobRun--
												break
											}
											zig += 0x0f
										}
									}
								}
							}
							if ns == 1 {
								if !advanceMCU() {
									return nil, 0, false
								}
							}
						}
					}
					if ns != 1 {
						if !advanceMCU() {
							return nil, 0, false
						}
					}
				}
			}
			if ivIdx < len(ivs) {
				consumed := br.consumedPos()
				curIv := ivs[ivIdx]
				if consumed > 0 && curIv.start+consumed < curIv.end {
					cut := curIv.start + consumed
					if cut > curIv.start && data[cut-1] == 0xFF {
						cut--
					}
					if cut > curIv.start {
						cuts = append(cuts, jpegCutSpan{cut: cut, end: curIv.end})
						totalTrim += curIv.end - cut
					}
				}
				for extra := ivIdx + 1; extra < len(ivs); extra++ {
					if ivs[extra].end > ivs[extra].start {
						cuts = append(cuts, jpegCutSpan{cut: ivs[extra].start, end: ivs[extra].end})
						totalTrim += ivs[extra].end - ivs[extra].start
					}
				}
			}
			off = scanEnd
			continue
		}
		off += 2 + segLen
	}
	return cuts, totalTrim, true
}

func verifyJPEGScansHaveNoTrailingCSPRNG(data []byte, scanSpans, rstSpans []jpegScanSpan, hasDRI, isSOF2 bool) bool {
	if len(scanSpans) > 0 {
		sortedScans := make([]jpegScanSpan, len(scanSpans))
		copy(sortedScans, scanSpans)
		sort.Slice(sortedScans, func(i, j int) bool {
			return (sortedScans[i].end - sortedScans[i].start) > (sortedScans[j].end - sortedScans[j].start)
		})
		checked := 0
		for _, sp := range sortedScans {
			if sp.end-sp.start < minEntropyBytes {
				break
			}
			if tryDecodeJPEGWithoutTail(data, sp.start, sp.end, minEntropyBytes) {
				return false
			}
			checked++
			if checked >= 16 {
				break
			}
		}
	}
	if (hasDRI && len(rstSpans) > 0) || (isSOF2 && len(scanSpans) >= 2) {
		if cuts, trimmedTotal, ok := findJPEGUnusedRSTSpans(data); ok && len(cuts) >= 1 && trimmedTotal >= minEntropyBytes {
			trunc := make([]byte, 0, len(data)-trimmedTotal)
			cur := 0
			for _, cs := range cuts {
				if cs.cut > cur {
					trunc = append(trunc, data[cur:cs.cut]...)
				}
				if cs.end > cur {
					cur = cs.end
				}
			}
			if cur < len(data) {
				trunc = append(trunc, data[cur:]...)
			}
			if _, err := jpeg.Decode(bytes.NewReader(trunc)); err == nil {
				return false
			}
		}
	}
	if hasDRI && len(rstSpans) > 0 {
		sortedRST := make([]jpegScanSpan, len(rstSpans))
		copy(sortedRST, rstSpans)
		sort.Slice(sortedRST, func(i, j int) bool {
			return (sortedRST[i].end - sortedRST[i].start) > (sortedRST[j].end - sortedRST[j].start)
		})
		checked := 0
		for _, iv := range sortedRST {
			if iv.end-iv.start < minEntropyBytes {
				break
			}
			if tryDecodeJPEGWithoutTail(data, iv.start, iv.end, minEntropyBytes) {
				return false
			}
			checked++
			if checked >= 4 {
				break
			}
		}
		// Simultaneous multi-interval trim across all RST intervals (including sub-8B spans and mixed/anchored intervals).
		type cutSpan struct {
			cut int
			end int
		}
		decodeWithCuts := func(cuts []cutSpan, totalTrimmed int) bool {
			if totalTrimmed < minEntropyBytes || len(cuts) < 2 {
				return false
			}
			sorted := make([]cutSpan, len(cuts))
			copy(sorted, cuts)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].cut < sorted[j].cut
			})
			trunc := make([]byte, 0, len(data)-totalTrimmed)
			cur := 0
			for _, cs := range sorted {
				if cs.cut > cur {
					trunc = append(trunc, data[cur:cs.cut]...)
				}
				if cs.end > cur {
					cur = cs.end
				}
			}
			if cur < len(data) {
				trunc = append(trunc, data[cur:]...)
			}
			_, err := jpeg.Decode(bytes.NewReader(trunc))
			return err == nil
		}
		buildCuts := func(spans []jpegScanSpan, minSpan int, trimFn func(spanLen int) int) ([]cutSpan, int) {
			var cuts []cutSpan
			totalTrimmed := 0
			for _, iv := range spans {
				spanLen := iv.end - iv.start
				if spanLen < minSpan {
					continue
				}
				trim := trimFn(spanLen)
				if trim <= 0 {
					continue
				}
				cut := iv.end - trim
				if cut > iv.start && data[cut-1] == 0xFF {
					cut--
				}
				if cut <= iv.start {
					continue
				}
				cuts = append(cuts, cutSpan{cut: cut, end: iv.end})
				totalTrimmed += iv.end - cut
			}
			return cuts, totalTrimmed
		}
		tryMultiIntervalTrim := func(spans []jpegScanSpan, minSpan int, trimFn func(spanLen int) int) bool {
			if len(spans) < 2 {
				return false
			}
			cuts, totalTrimmed := buildCuts(spans, minSpan, trimFn)
			return decodeWithCuts(cuts, totalTrimmed)
		}
		trimKeep4 := func(spanLen int) int { return min(128, spanLen-4) }
		trimHalf := func(spanLen int) int { return min(128, spanLen/2) }
		if tryMultiIntervalTrim(rstSpans, 5, trimKeep4) {
			return false
		}
		if tryMultiIntervalTrim(rstSpans, 16, trimHalf) {
			return false
		}
		if len(rstSpans) >= 4 {
			mid := len(rstSpans) / 2
			if tryMultiIntervalTrim(rstSpans[:mid], 5, trimKeep4) || tryMultiIntervalTrim(rstSpans[mid:], 5, trimKeep4) {
				return false
			}
		}
		// Adaptive fallback for mixed/anchored RST intervals:
		// 1) Try top-K longest spans (catches padded spans mixed among shorter genuine AC intervals).
		for _, frac := range []int{2, 4, 8, 16} {
			k := len(sortedRST) / frac
			if k >= 2 && tryMultiIntervalTrim(sortedRST[:k], 5, trimKeep4) {
				return false
			}
		}
		// 2) Bounded binary-partition anchor pruning: isolate trimmable sub-ranges while dropping failing anchors.
		var candSpans []jpegScanSpan
		for _, iv := range rstSpans {
			if iv.end-iv.start >= 5 {
				candSpans = append(candSpans, iv)
			}
		}
		if len(candSpans) >= 16 {
			var sampledConfirmed []cutSpan
			sampledTrim := 0
			for sIdx := 0; sIdx < 16; sIdx++ {
				iv := candSpans[sIdx*len(candSpans)/16]
				trim := trimKeep4(iv.end - iv.start)
				if trim <= 0 {
					continue
				}
				if tryDecodeJPEGWithoutTail(data, iv.start, iv.end, trim) {
					cut := iv.end - trim
					if cut > iv.start && data[cut-1] == 0xFF {
						cut--
					}
					if cut > iv.start {
						sampledConfirmed = append(sampledConfirmed, cutSpan{cut: cut, end: iv.end})
						sampledTrim += iv.end - cut
					}
				}
			}
			if sampledTrim >= minEntropyBytes && decodeWithCuts(sampledConfirmed, sampledTrim) {
				return false
			}
		}
		if len(candSpans) >= 2 {
			var confirmed []cutSpan
			confirmedTrim := 0
			decodeBudget := 28
			var collectTrimmable func(spans []jpegScanSpan)
			collectTrimmable = func(spans []jpegScanSpan) {
				if len(spans) == 0 || decodeBudget <= 0 || confirmedTrim >= minEntropyBytes*2 {
					return
				}
				cuts, trimAmt := buildCuts(spans, 5, trimKeep4)
				if trimAmt == 0 || len(cuts) == 0 {
					return
				}
				decodeBudget--
				sorted := make([]cutSpan, len(cuts))
				copy(sorted, cuts)
				sort.Slice(sorted, func(i, j int) bool {
					return sorted[i].cut < sorted[j].cut
				})
				trunc := make([]byte, 0, len(data)-trimAmt)
				cur := 0
				for _, cs := range sorted {
					if cs.cut > cur {
						trunc = append(trunc, data[cur:cs.cut]...)
					}
					if cs.end > cur {
						cur = cs.end
					}
				}
				if cur < len(data) {
					trunc = append(trunc, data[cur:]...)
				}
				if _, err := jpeg.Decode(bytes.NewReader(trunc)); err == nil {
					confirmed = append(confirmed, cuts...)
					confirmedTrim += trimAmt
					return
				}
				if len(spans) == 1 || trimAmt < 32 {
					return
				}
				mid := len(spans) / 2
				collectTrimmable(spans[:mid])
				collectTrimmable(spans[mid:])
			}
			collectTrimmable(candSpans)
			if decodeWithCuts(confirmed, confirmedTrim) {
				return false
			}
		}
	}
	return true
}

func validateJPEGScans(
	data []byte,
	scanStart int,
	totalDQTTables, totalDQTBytes, totalDHTTables *int,
	allDQTPayload *[]byte,
) (int, []jpegScanSpan, []jpegScanSpan, bool) {
	i := scanStart
	segStart := scanStart
	scanBodyStart := scanStart
	ivStart := scanStart
	inScanBody := true
	rstInCurScan := false
	totalScanBytes := 0
	var scanSpans []jpegScanSpan
	var rstSpans []jpegScanSpan

	checkEntropySlice := func(end int) bool {
		if end <= segStart {
			return true
		}
		seg := data[segStart:end]
		totalScanBytes += len(seg)
		c := collapseRepeatedPeriodic(seg, 8, 4)
		if len(c) >= 48 && distinctBytesCount(c) >= 5 && shannonEntropy(c) >= 2.5 {
			if hasHighPrintableAscii(c) || len(extractPrintableTextRuns(c, 48)) > 0 {
				return false
			}
		}
		stripped := stripControlBytesForInspection(seg)
		if len(stripped) != len(seg) {
			cs := collapseRepeatedPeriodic(stripped, 8, 4)
			if len(cs) >= 48 && distinctBytesCount(cs) >= 5 && shannonEntropy(cs) >= 2.5 {
				if hasHighPrintableAscii(cs) || len(extractPrintableTextRuns(cs, 48)) > 0 {
					return false
				}
			}
		}
		return true
	}
	for i < len(data) {
		if data[i] != 0xFF {
			i++
			continue
		}
		if i+1 >= len(data) {
			return 0, nil, nil, false
		}
		next := data[i+1]
		switch {
		case next == 0x00:
			i += 2
		case next == 0xFF:
			i++
		case next >= 0xD0 && next <= 0xD7:
			if inScanBody && i > ivStart {
				rstSpans = append(rstSpans, jpegScanSpan{start: ivStart, end: i})
				rstInCurScan = true
			}
			i += 2
			ivStart = i
		case next == 0xD9:
			if i+2 != len(data) {
				return 0, nil, nil, false
			}
			if inScanBody {
				if !checkEntropySlice(i) {
					return 0, nil, nil, false
				}
				if i > scanBodyStart {
					scanSpans = append(scanSpans, jpegScanSpan{start: scanBodyStart, end: i})
				}
				if rstInCurScan && i > ivStart {
					rstSpans = append(rstSpans, jpegScanSpan{start: ivStart, end: i})
				}
			}
			return totalScanBytes, scanSpans, rstSpans, true
		case next == 0xDA || next == 0xC4 || next == 0xDB || next == 0xDD || (next >= 0xE0 && next <= 0xFE):
			if inScanBody {
				if !checkEntropySlice(i) {
					return 0, nil, nil, false
				}
				if i > scanBodyStart {
					scanSpans = append(scanSpans, jpegScanSpan{start: scanBodyStart, end: i})
				}
				if rstInCurScan && i > ivStart {
					rstSpans = append(rstSpans, jpegScanSpan{start: ivStart, end: i})
				}
				inScanBody = false
			}
			if i+4 > len(data) {
				return 0, nil, nil, false
			}
			segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
			if segLen < 2 || i+2+segLen > len(data) {
				return 0, nil, nil, false
			}
			segPayload := data[i+4 : i+2+segLen]
			if next == 0xDD && segLen != 4 {
				return 0, nil, nil, false
			}
			if next == 0xDB {
				nonTriv, nTbl := extractNonTrivialDQTTables(segPayload)
				if nTbl == 0 || validDQTSegmentTables(segPayload) == 0 {
					return 0, nil, nil, false
				}
				*totalDQTTables += nTbl
				*totalDQTBytes += len(segPayload)
				if *totalDQTTables > 16 || *totalDQTBytes > 2048 {
					return 0, nil, nil, false
				}
				*allDQTPayload = append(*allDQTPayload, nonTriv...)
			}
			if next == 0xC4 {
				nTbl := validDHTSegmentTables(segPayload)
				if nTbl == 0 {
					return 0, nil, nil, false
				}
				*totalDHTTables += nTbl
				if *totalDHTTables > 24 {
					return 0, nil, nil, false
				}
			}
			i += 2 + segLen
			segStart = i
			if next == 0xDA {
				inScanBody = true
				scanBodyStart = i
				ivStart = i
				rstInCurScan = false
			}
		default:
			return 0, nil, nil, false
		}
	}
	return 0, nil, nil, false
}

func isValidJPEGStructure(data []byte) bool {
	if len(data) < 16 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
		return false
	}
	off := 2
	seenSOF := false
	seenDQT := false
	seenDHT := false
	hasDRI := false
	totalDQTTables := 0
	totalDQTBytes := 0
	totalDHTTables := 0
	var allDQTPayload []byte
	var sofMarker byte
	var sofW, sofH, sofComp int
	for off+1 < len(data) {
		for off+1 < len(data) && data[off] == 0xFF && data[off+1] == 0xFF {
			off++
		}
		if off+1 >= len(data) || data[off] != 0xFF {
			return false
		}
		m := data[off+1]
		if m == 0x00 || m == 0xD8 || m == 0xD9 {
			return false
		}
		if m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			off += 2
			continue
		}
		if off+4 > len(data) {
			return false
		}
		segLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if segLen < 2 || off+2+segLen > len(data) {
			return false
		}
		segPayload := data[off+4 : off+2+segLen]
		switch {
		case m == 0xDB:
			nonTriv, nTbl := extractNonTrivialDQTTables(segPayload)
			if nTbl == 0 || validDQTSegmentTables(segPayload) == 0 {
				return false
			}
			totalDQTTables += nTbl
			totalDQTBytes += len(segPayload)
			if totalDQTTables > 16 || totalDQTBytes > 2048 {
				return false
			}
			allDQTPayload = append(allDQTPayload, nonTriv...)
			seenDQT = true
		case m == 0xC4:
			nTbl := validDHTSegmentTables(segPayload)
			if nTbl == 0 {
				return false
			}
			totalDHTTables += nTbl
			if totalDHTTables > 24 {
				return false
			}
			seenDHT = true
		case m == 0xDD:
			if segLen != 4 {
				return false
			}
			hasDRI = true
		case isJPEGSOFMarker(m):
			if segLen < 8 {
				return false
			}
			h := int(binary.BigEndian.Uint16(segPayload[1:3]))
			w := int(binary.BigEndian.Uint16(segPayload[3:5]))
			nf := int(segPayload[5])
			if h == 0 || w == 0 || nf == 0 || segLen != 8+3*nf {
				return false
			}
			seenSOF = true
			sofMarker = m
			sofH = h
			sofW = w
			sofComp = nf
		}
		if m == 0xDA {
			if !seenSOF || !seenDQT {
				return false
			}
			if isJPEGProbablyHuffmanSOF(sofMarker) && !seenDHT {
				return false
			}
			scanStart := off + 2 + segLen
			if scanStart+2 > len(data) {
				return false
			}
			totalScanBytes, scanSpans, rstSpans, scanOK := validateJPEGScans(data, scanStart, &totalDQTTables, &totalDQTBytes, &totalDHTTables, &allDQTPayload)
			if !scanOK {
				return false
			}
			if len(allDQTPayload) >= minEntropyBytes && hasConcealedHighEntropy(allDQTPayload) {
				return false
			}
			if totalScanBytes >= minEntropyBytes {
				if int64(sofW)*int64(sofH) > 64_000_000 {
					return false
				}
				maxPlausible := max(int64(4096), int64(4)*int64(sofW)*int64(sofH)*int64(sofComp))
				if int64(totalScanBytes) > maxPlausible {
					return false
				}
				if sofW >= 64 && sofH >= 64 {
					minBlocks := (sofW / 16) * (sofH / 16)
					if totalScanBytes < minBlocks/8 {
						return false
					}
				}
				decodedClean := false
				if sofMarker == 0xC0 || sofMarker == 0xC1 || sofMarker == 0xC2 {
					if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
						if _, isUnsupported := err.(jpeg.UnsupportedError); !isUnsupported {
							if sofMarker == 0xC2 && hasDRI {
								if _, totalTrim, ok := findJPEGUnusedRSTSpans(data); ok && totalTrim < minEntropyBytes {
									if verifyJPEGScansHaveNoTrailingCSPRNG(data, scanSpans, rstSpans, hasDRI, true) {
										decodedClean = true
									}
								}
							}
							if !decodedClean {
								return false
							}
						}
					} else {
						decodedClean = true
						if !verifyJPEGScansHaveNoTrailingCSPRNG(data, scanSpans, rstSpans, hasDRI, sofMarker == 0xC2) {
							return false
						}
					}
				}
				if !decodedClean {
					var aggScan bytes.Buffer
					for _, sp := range scanSpans {
						if sp.end <= sp.start {
							continue
						}
						seg := data[sp.start:sp.end]
						if len(seg) >= minEntropyBytes {
							if _, highEnt := checkHighEntropy(seg); highEnt {
								return false
							}
							if hasConcealedHighEntropy(seg) || hasBitAgnosticIncompressible(seg, 6.40, 0.88) {
								return false
							}
							stripped := stripControlBytesForInspection(seg)
							if len(stripped) >= minEntropyBytes && len(stripped) < len(seg)*9/10 {
								if _, highEnt := checkHighEntropy(stripped); highEnt {
									return false
								}
								if hasConcealedHighEntropy(stripped) || hasBitAgnosticIncompressible(stripped, 6.40, 0.88) {
									return false
								}
							}
						}
						if aggScan.Len() < maxDecodedSegmentBytes {
							rem := maxDecodedSegmentBytes - aggScan.Len()
							if len(seg) > rem {
								aggScan.Write(seg[:rem])
							} else {
								aggScan.Write(seg)
							}
						}
					}
					if aggScan.Len() >= minEntropyBytes {
						agg := aggScan.Bytes()
						if _, highEnt := checkHighEntropy(agg); highEnt {
							return false
						}
						if hasConcealedHighEntropy(agg) || hasBitAgnosticIncompressible(agg, 6.40, 0.88) {
							return false
						}
					}
				}
			}
			return true
		}
		off += 2 + segLen
	}
	return false
}

func isValidJFIFOrJFXX(segPayload []byte) (valid bool, thumbJPEG []byte) {
	if len(segPayload) >= 14 && bytes.HasPrefix(segPayload, []byte("JFIF\x00")) {
		w := int(segPayload[12])
		h := int(segPayload[13])
		if len(segPayload) == 14+3*w*h {
			return true, nil
		}
		return false, nil
	}
	if len(segPayload) >= 6 && bytes.HasPrefix(segPayload, []byte("JFXX\x00")) {
		switch segPayload[5] {
		case 0x10:
			if isValidJPEGStructure(segPayload[6:]) {
				return true, segPayload[6:]
			}
		case 0x11:
			if len(segPayload) >= 8+768 {
				w, h := int(segPayload[6]), int(segPayload[7])
				if len(segPayload) == 8+768+w*h {
					return true, nil
				}
			}
		case 0x13:
			if len(segPayload) >= 8 {
				w, h := int(segPayload[6]), int(segPayload[7])
				if len(segPayload) == 8+3*w*h {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func inspectJPEGPhotoshop8BIM(
	ctx context.Context,
	virtualPath string,
	segPayload []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	const prefix = "Photoshop 3.0\x00"
	pos := len(prefix)
	if len(segPayload) <= pos {
		inspectAncillaryPayload(ctx, virtualPath, "#jpeg_ed", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		return
	}
	type bimBlock struct {
		resID uint16
		data  []byte
	}
	var blocks []bimBlock
	for pos < len(segPayload) {
		if pos+12 > len(segPayload) || string(segPayload[pos:pos+4]) != "8BIM" {
			inspectAncillaryPayload(ctx, virtualPath, "#jpeg_ed", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			return
		}
		resID := binary.BigEndian.Uint16(segPayload[pos+4 : pos+6])
		nameLen := int(segPayload[pos+6])
		nameTotal := 1 + nameLen
		if nameTotal%2 != 0 {
			nameTotal++
		}
		pos += 6 + nameTotal
		if pos+4 > len(segPayload) {
			inspectAncillaryPayload(ctx, virtualPath, "#jpeg_ed", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			return
		}
		dataSize := int(binary.BigEndian.Uint32(segPayload[pos : pos+4]))
		pos += 4
		if dataSize < 0 || pos+dataSize > len(segPayload) {
			inspectAncillaryPayload(ctx, virtualPath, "#jpeg_ed", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			return
		}
		blockData := segPayload[pos : pos+dataSize]
		blocks = append(blocks, bimBlock{resID: resID, data: blockData})
		pos += dataSize
		if dataSize%2 != 0 && pos < len(segPayload) {
			pos++
		}
	}
	if len(blocks) == 0 || pos != len(segPayload) {
		inspectAncillaryPayload(ctx, virtualPath, "#jpeg_ed", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		return
	}
	for idx, blk := range blocks {
		if blk.resID == 0x0409 || blk.resID == 0x040C {
			if soi := bytes.Index(blk.data, []byte{0xFF, 0xD8, 0xFF}); soi >= 0 {
				if eoiRel := findEmbeddedJPEGEnd(blk.data[soi:]); eoiRel > 0 {
					thumb := blk.data[soi : soi+eoiRel]
					if isValidJPEGStructure(thumb) {
						inspectJPEGMetadataSegments(ctx, fmt.Sprintf("%s#jpeg_ed_thumb[%d]", virtualPath, idx), thumb, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
						if soi > 0 {
							inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed_pre[%d]", idx), blk.data[:soi], archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
						}
						if soi+eoiRel < len(blk.data) {
							inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed_post[%d]", idx), blk.data[soi+eoiRel:], archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
						}
						continue
					}
				}
			}
			inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed[%d]", idx), blk.data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			continue
		}
		if blk.resID == 0x040F {
			if isValidICCProfileHeaderAndTags(blk.data) {
				inspectValidatedICCProfile(ctx, virtualPath, fmt.Sprintf("#jpeg_ed_icc[%d]", idx), blk.data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			} else {
				inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed[%d]", idx), blk.data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
			continue
		}
		if blk.resID == 0x0422 || blk.resID == 0x0423 {
			inspectExifPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed_exif[%d]", idx), blk.data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			continue
		}
		inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_ed[%d]", idx), blk.data, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
	}
}

func inspectJPEGMetadataSegments(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if len(data) < 4 {
		return
	}
	type iccChunk struct {
		seqNo     byte
		numChunks byte
		rawSeg    []byte
		payload   []byte
	}
	var iccChunks []iccChunk
	iccTotalBytes := 0

	inspectPrintableAndCreds := func(suffix string, payload []byte) {
		stripped := stripControlBytesForInspection(payload)
		emitCredentialFindings(virtualPath, payload, res)
		if len(stripped) > 0 && len(stripped) != len(payload) {
			emitCredentialFindings(virtualPath, stripped, res)
		}
		if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
			subPath := virtualPath + suffix
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    subPath,
				Data:           extracted,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: true,
			})
			emitCredentialFindings(subPath, extracted, res)
			if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
				inspectEncodedPayloads(ctx, subPath, extracted, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
			}
		}
	}

	off := 2
	inspectSeg := func(m byte, segPayload []byte) {
		switch {
		case m == 0xE0:
			if valid, thumb := isValidJFIFOrJFXX(segPayload); valid {
				if len(thumb) > 0 {
					inspectJPEGMetadataSegments(ctx, virtualPath+"#jpeg_e0_thumb", thumb, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
				} else {
					pixelOff := 14
					if bytes.HasPrefix(segPayload, []byte("JFXX\x00")) {
						pixelOff = 8
					}
					if len(segPayload) > pixelOff {
						inspectAncillaryPayload(ctx, virtualPath, "#jpeg_e0_thumb", segPayload[pixelOff:], archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					}
				}
				inspectPrintableAndCreds("#jpeg_e0", segPayload)
			} else {
				inspectAncillaryPayload(ctx, virtualPath, "#jpeg_e0", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
		case m == 0xE1:
			inspectExifPayload(ctx, virtualPath, "#jpeg_e1", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		case m == 0xE2 && bytes.HasPrefix(segPayload, []byte("ICC_PROFILE\x00")):
			if len(segPayload) < 14 || segPayload[12] == 0 || segPayload[13] == 0 || segPayload[12] > segPayload[13] || iccTotalBytes+len(segPayload) > defaultArchiveMaxEntryBytes {
				inspectAncillaryPayload(ctx, virtualPath, "#jpeg_e2", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
				return
			}
			iccTotalBytes += len(segPayload)
			iccChunks = append(iccChunks, iccChunk{
				seqNo:     segPayload[12],
				numChunks: segPayload[13],
				rawSeg:    segPayload,
				payload:   segPayload[14:],
			})
		case m == 0xED && bytes.HasPrefix(segPayload, []byte("Photoshop 3.0\x00")):
			inspectJPEGPhotoshop8BIM(ctx, virtualPath, segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		case m == 0xDB:
			if !isValidDQTSegment(segPayload) {
				inspectAncillaryPayload(ctx, virtualPath, "#jpeg_db", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			} else {
				inspectPrintableAndCreds("#jpeg_db", segPayload)
			}
		case m == 0xC4:
			if !isValidDHTSegment(segPayload) {
				inspectAncillaryPayload(ctx, virtualPath, "#jpeg_c4", segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			} else {
				inspectPrintableAndCreds("#jpeg_c4", segPayload)
			}
		case m == 0xFE || (m >= 0xE1 && m <= 0xEF):
			inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#jpeg_%02x", m), segPayload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		}
	}

	inScan := false
	for off+1 < len(data) {
		if !inScan {
			for off+1 < len(data) && data[off] == 0xFF && data[off+1] == 0xFF {
				off++
			}
			if off+1 >= len(data) || data[off] != 0xFF {
				break
			}
			m := data[off+1]
			if m == 0xD9 {
				break
			}
			if m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
				off += 2
				continue
			}
			if off+4 > len(data) {
				break
			}
			segLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
			if segLen < 2 || off+2+segLen > len(data) {
				break
			}
			segPayload := data[off+4 : off+2+segLen]
			inspectSeg(m, segPayload)
			off += 2 + segLen
			if m == 0xDA {
				inScan = true
			}
			continue
		}
		if data[off] != 0xFF {
			off++
			continue
		}
		next := data[off+1]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			off += 2
			continue
		}
		if next == 0xFF {
			off++
			continue
		}
		if next == 0xD9 {
			break
		}
		if off+4 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if segLen < 2 || off+2+segLen > len(data) {
			break
		}
		segPayload := data[off+4 : off+2+segLen]
		inspectSeg(next, segPayload)
		off += 2 + segLen
	}

	if len(iccChunks) > 0 {
		expectedCount := int(iccChunks[0].numChunks)
		allMatchCount := expectedCount > 0 && len(iccChunks) == expectedCount
		bySeq := make(map[byte][]byte, len(iccChunks))
		for _, ch := range iccChunks {
			if int(ch.numChunks) != expectedCount {
				allMatchCount = false
			}
			if _, dup := bySeq[ch.seqNo]; dup {
				allMatchCount = false
			}
			bySeq[ch.seqNo] = ch.payload
		}
		var fullICC []byte
		if allMatchCount {
			for s := 1; s <= expectedCount; s++ {
				part, ok := bySeq[byte(s)]
				if !ok {
					allMatchCount = false
					break
				}
				fullICC = append(fullICC, part...)
			}
		}
		if allMatchCount && isValidICCProfileHeaderAndTags(fullICC) {
			inspectValidatedICCProfile(ctx, virtualPath, "#jpeg_app2_iccp", fullICC, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		} else {
			for _, ch := range iccChunks {
				inspectAncillaryPayload(ctx, virtualPath, "#jpeg_app2_iccp", ch.payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
		}
	}
}

type vp8lBitReader struct {
	data     []byte
	idx      int
	buf      uint64
	nBits    int
	overread bool
}

func (r *vp8lBitReader) fill() {
	for r.nBits <= 56 && r.idx < len(r.data) {
		r.buf |= uint64(r.data[r.idx]) << uint(r.nBits)
		r.idx++
		r.nBits += 8
	}
}

func (r *vp8lBitReader) readBits(n int) (uint32, bool) {
	if n == 0 {
		return 0, true
	}
	r.fill()
	if r.nBits < n {
		r.overread = true
		return 0, false
	}
	v := uint32(r.buf & ((uint64(1) << uint(n)) - 1))
	r.buf >>= uint(n)
	r.nBits -= n
	return v, true
}

func (r *vp8lBitReader) bytesUsed() int {
	bits := r.idx*8 - r.nBits
	if bits < 0 {
		return 0
	}
	return (bits + 7) / 8
}

type vp8lHuffTree struct {
	empty     bool
	isSingle  bool
	singleSym uint16
	table     [1 << 8]uint32 // bits <= 8 fast LUT: low 16 = sym, high 16 = bitLen (0 => >8 bits)
	longCodes []uint32
	longSyms  []uint16
	longLens  []uint8
	maxLen    int
}

func buildVP8LHuffTree(lengths []uint8) (vp8lHuffTree, bool) {
	var t vp8lHuffTree
	var counts [16]int
	maxLen := 0
	nonZero := 0
	onlySym := uint16(0)
	for i, l := range lengths {
		if l > 15 {
			return t, false
		}
		if l > 0 {
			counts[l]++
			if int(l) > maxLen {
				maxLen = int(l)
			}
			nonZero++
			onlySym = uint16(i)
		}
	}
	if nonZero == 0 {
		t.empty = true
		return t, true
	}
	if nonZero == 1 {
		if maxLen != 1 {
			return t, false
		}
		t.isSingle = true
		t.singleSym = onlySym
		return t, true
	}
	t.maxLen = maxLen
	left := 1
	for bits := 1; bits <= maxLen; bits++ {
		left <<= 1
		left -= counts[bits]
		if left < 0 {
			return t, false
		}
	}
	if left != 0 {
		return t, false
	}
	var nextCode [16]uint32
	code := uint32(0)
	for bits := 1; bits <= maxLen; bits++ {
		code = (code + uint32(counts[bits-1])) << 1
		nextCode[bits] = code
	}
	for sym, l := range lengths {
		if l == 0 {
			continue
		}
		c := nextCode[l]
		nextCode[l]++
		// Reverse l bits because VP8L packs LSB-first.
		rev := uint32(0)
		for b := uint8(0); b < l; b++ {
			rev = (rev << 1) | ((c >> b) & 1)
		}
		if l <= 8 {
			entry := uint32(sym) | (uint32(l) << 16)
			step := 1 << l
			for idx := int(rev); idx < len(t.table); idx += step {
				t.table[idx] = entry
			}
		} else {
			t.longCodes = append(t.longCodes, rev)
			t.longSyms = append(t.longSyms, uint16(sym))
			t.longLens = append(t.longLens, l)
		}
	}
	return t, true
}

func (t *vp8lHuffTree) readSymbol(r *vp8lBitReader) (uint16, bool) {
	if t.empty {
		return 0, false
	}
	if t.isSingle {
		return t.singleSym, true
	}
	r.fill()
	if r.nBits == 0 {
		r.overread = true
		return 0, false
	}
	idx := uint32(r.buf & 0xff)
	entry := t.table[idx]
	if entry != 0 {
		bitLen := int(entry >> 16)
		if r.nBits < bitLen {
			r.overread = true
			return 0, false
		}
		r.buf >>= uint(bitLen)
		r.nBits -= bitLen
		return uint16(entry & 0xffff), true
	}
	for i, c := range t.longCodes {
		l := int(t.longLens[i])
		if r.nBits >= l && uint32(r.buf&((uint64(1)<<uint(l))-1)) == c {
			r.buf >>= uint(l)
			r.nBits -= l
			return t.longSyms[i], true
		}
	}
	r.overread = true
	return 0, false
}

var vp8lCodeLengthOrder = [19]int{17, 18, 0, 1, 2, 3, 4, 5, 16, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func readVP8LHuffmanTree(r *vp8lBitReader, alphabetSize int) (vp8lHuffTree, bool) {
	var t vp8lHuffTree
	simple, ok := r.readBits(1)
	if !ok {
		return t, false
	}
	if simple == 1 {
		numSymBits, ok1 := r.readBits(1)
		isFirst8, ok2 := r.readBits(1)
		if !ok1 || !ok2 {
			return t, false
		}
		symBits := 1
		if isFirst8 == 1 {
			symBits = 8
		}
		sym0, ok3 := r.readBits(symBits)
		if !ok3 || int(sym0) >= alphabetSize {
			return t, false
		}
		if numSymBits == 0 {
			t.isSingle = true
			t.singleSym = uint16(sym0)
			return t, true
		}
		sym1, ok4 := r.readBits(8)
		if !ok4 || int(sym1) >= alphabetSize || sym1 == sym0 {
			return t, false
		}
		lens := make([]uint8, alphabetSize)
		lens[sym0] = 1
		lens[sym1] = 1
		return buildVP8LHuffTree(lens)
	}
	numCodeLensB, ok := r.readBits(4)
	if !ok {
		return t, false
	}
	numCodeLens := int(numCodeLensB) + 4
	var codeLenLens [19]uint8
	for i := 0; i < numCodeLens; i++ {
		v, ok := r.readBits(3)
		if !ok {
			return t, false
		}
		codeLenLens[vp8lCodeLengthOrder[i]] = uint8(v)
	}
	codeLenTree, ok := buildVP8LHuffTree(codeLenLens[:])
	if !ok || codeLenTree.empty {
		return t, false
	}
	useMaxSym, ok := r.readBits(1)
	if !ok {
		return t, false
	}
	maxSym := alphabetSize
	if useMaxSym == 1 {
		lenBitsB, ok1 := r.readBits(3)
		if !ok1 {
			return t, false
		}
		lenBits := 2 + 2*int(lenBitsB)
		ms, ok2 := r.readBits(lenBits)
		if !ok2 {
			return t, false
		}
		maxSym = int(ms) + 2
		if maxSym > alphabetSize {
			return t, false
		}
	}
	lens := make([]uint8, alphabetSize)
	prevCodeLen := uint8(8)
	sym := 0
	for sym < alphabetSize {
		if maxSym == 0 {
			break
		}
		maxSym--
		code, ok := codeLenTree.readSymbol(r)
		if !ok {
			return t, false
		}
		switch {
		case code < 16:
			lens[sym] = uint8(code)
			sym++
			if code > 0 {
				prevCodeLen = uint8(code)
			}
		case code == 16:
			repB, ok := r.readBits(2)
			if !ok {
				return t, false
			}
			rep := int(repB) + 3
			if sym+rep > alphabetSize {
				return t, false
			}
			for k := 0; k < rep; k++ {
				lens[sym] = prevCodeLen
				sym++
			}
		case code == 17:
			repB, ok := r.readBits(3)
			if !ok {
				return t, false
			}
			rep := int(repB) + 3
			if sym+rep > alphabetSize {
				return t, false
			}
			sym += rep
		case code == 18:
			repB, ok := r.readBits(7)
			if !ok {
				return t, false
			}
			rep := int(repB) + 11
			if sym+rep > alphabetSize {
				return t, false
			}
			sym += rep
		default:
			return t, false
		}
	}
	return buildVP8LHuffTree(lens)
}

var vp8lDistanceMap = [120][2]int8{
	{0, 1}, {1, 0}, {1, 1}, {-1, 1}, {0, 2}, {2, 0}, {1, 2}, {-1, 2},
	{2, 1}, {-2, 1}, {2, 2}, {-2, 2}, {0, 3}, {3, 0}, {1, 3}, {-1, 3},
	{3, 1}, {-3, 1}, {2, 3}, {-2, 3}, {3, 2}, {-3, 2}, {0, 4}, {4, 0},
	{1, 4}, {-1, 4}, {4, 1}, {-4, 1}, {3, 3}, {-3, 3}, {2, 4}, {-2, 4},
	{4, 2}, {-4, 2}, {0, 5}, {3, 4}, {-3, 4}, {4, 3}, {-4, 3}, {5, 0},
	{1, 5}, {-1, 5}, {5, 1}, {-5, 1}, {2, 5}, {-2, 5}, {5, 2}, {-5, 2},
	{4, 4}, {-4, 4}, {3, 5}, {-3, 5}, {5, 3}, {-5, 3}, {0, 6}, {6, 0},
	{1, 6}, {-1, 6}, {6, 1}, {-6, 1}, {2, 6}, {-2, 6}, {6, 2}, {-6, 2},
	{4, 5}, {-4, 5}, {5, 4}, {-5, 4}, {3, 6}, {-3, 6}, {6, 3}, {-6, 3},
	{0, 7}, {7, 0}, {1, 7}, {-1, 7}, {5, 5}, {-5, 5}, {7, 1}, {-7, 1},
	{4, 6}, {-4, 6}, {6, 4}, {-6, 4}, {2, 7}, {-2, 7}, {7, 2}, {-7, 2},
	{3, 7}, {-3, 7}, {7, 3}, {-7, 3}, {5, 6}, {-5, 6}, {6, 5}, {-6, 5},
	{8, 0}, {4, 7}, {-4, 7}, {7, 4}, {-7, 4}, {8, 1}, {8, 2}, {6, 6},
	{-6, 6}, {8, 3}, {5, 7}, {-5, 7}, {7, 5}, {-7, 5}, {8, 4}, {6, 7},
	{-6, 7}, {7, 6}, {-7, 6}, {8, 5}, {7, 7}, {-7, 7}, {8, 6}, {8, 7},
}

func vp8lPrefixValue(r *vp8lBitReader, code int) (int, bool) {
	if code < 4 {
		return code + 1, true
	}
	extraBits := (code - 2) >> 1
	offset := (2 + (code & 1)) << uint(extraBits)
	extra, ok := r.readBits(extraBits)
	if !ok {
		return 0, false
	}
	return offset + int(extra) + 1, true
}

func decodeVP8LImageStream(r *vp8lBitReader, w, h int, topLevel, recordPixels bool, streamBytes int) ([]uint32, bool) {
	if w <= 0 || h <= 0 || int64(w)*int64(h) > 64_000_000 {
		return nil, false
	}
	codedW := w
	if topLevel {
		seenTransforms := uint32(0)
		for {
			hasTransform, ok := r.readBits(1)
			if !ok {
				return nil, false
			}
			if hasTransform == 0 {
				break
			}
			tType, ok := r.readBits(2)
			if !ok || (seenTransforms&(1<<tType)) != 0 {
				return nil, false
			}
			seenTransforms |= 1 << tType
			switch tType {
			case 0, 1:
				sb, ok := r.readBits(3)
				if !ok {
					return nil, false
				}
				sizeBits := int(sb) + 2
				subW := (codedW + (1 << uint(sizeBits)) - 1) >> uint(sizeBits)
				subH := (h + (1 << uint(sizeBits)) - 1) >> uint(sizeBits)
				if _, ok := decodeVP8LImageStream(r, subW, subH, false, false, streamBytes); !ok {
					return nil, false
				}
			case 2:
				// Subtract green transform: zero payload bits.
			case 3:
				nb, ok := r.readBits(8)
				if !ok {
					return nil, false
				}
				numColors := int(nb) + 1
				widthBits := 0
				switch {
				case numColors <= 2:
					widthBits = 3
				case numColors <= 4:
					widthBits = 2
				case numColors <= 16:
					widthBits = 1
				}
				if _, ok := decodeVP8LImageStream(r, numColors, 1, false, false, streamBytes); !ok {
					return nil, false
				}
				codedW = (codedW + (1 << uint(widthBits)) - 1) >> uint(widthBits)
			}
		}
	}

	totalPixels := int64(codedW) * int64(h)
	if totalPixels <= 0 || totalPixels > 64_000_000 {
		return nil, false
	}
	if totalPixels > int64(streamBytes)*32768+4096 {
		return nil, false
	}

	hasCC, ok := r.readBits(1)
	if !ok {
		return nil, false
	}
	colorCacheBits := 0
	colorCacheSize := 0
	if hasCC == 1 {
		ccb, ok := r.readBits(4)
		if !ok || ccb == 0 || ccb > 11 {
			return nil, false
		}
		colorCacheBits = int(ccb)
		colorCacheSize = 1 << uint(colorCacheBits)
	}

	huffBits := 0
	entW := 0
	var entPixels []uint32
	numHuffGroups := 1
	if topLevel {
		hasMeta, ok := r.readBits(1)
		if !ok {
			return nil, false
		}
		if hasMeta == 1 {
			hb, ok := r.readBits(3)
			if !ok {
				return nil, false
			}
			huffBits = int(hb) + 2
			entW = (codedW + (1 << uint(huffBits)) - 1) >> uint(huffBits)
			entH := (h + (1 << uint(huffBits)) - 1) >> uint(huffBits)
			if int64(entW)*int64(entH) > 1_000_000 {
				return nil, false
			}
			var okEnt bool
			entPixels, okEnt = decodeVP8LImageStream(r, entW, entH, false, true, streamBytes)
			if !okEnt || len(entPixels) != entW*entH {
				return nil, false
			}
			maxGrp := 0
			for _, px := range entPixels {
				grp := int((px >> 8) & 0xffff)
				if grp > maxGrp {
					maxGrp = grp
				}
			}
			numHuffGroups = maxGrp + 1
			if numHuffGroups > entW*entH || numHuffGroups > 65536 {
				return nil, false
			}
		}
	}

	type huffGroup struct {
		trees [5]vp8lHuffTree
	}
	groups := make([]huffGroup, numHuffGroups)
	greenAlph := 256 + 24 + colorCacheSize
	for g := 0; g < numHuffGroups; g++ {
		var ok bool
		if groups[g].trees[0], ok = readVP8LHuffmanTree(r, greenAlph); !ok {
			return nil, false
		}
		if groups[g].trees[1], ok = readVP8LHuffmanTree(r, 256); !ok {
			return nil, false
		}
		if groups[g].trees[2], ok = readVP8LHuffmanTree(r, 256); !ok {
			return nil, false
		}
		if groups[g].trees[3], ok = readVP8LHuffmanTree(r, 256); !ok {
			return nil, false
		}
		if groups[g].trees[4], ok = readVP8LHuffmanTree(r, 40); !ok {
			return nil, false
		}
	}

	var pixels []uint32
	if recordPixels {
		if totalPixels > 1_000_000 {
			return nil, false
		}
		pixels = make([]uint32, int(totalPixels))
	}
	var colorCache []uint32
	if recordPixels && colorCacheSize > 0 {
		colorCache = make([]uint32, colorCacheSize)
	}

	nPix := int(totalPixels)
	pos := 0
	for pos < nPix {
		grpIdx := 0
		if len(entPixels) > 0 {
			x := pos % codedW
			y := pos / codedW
			ei := (y>>uint(huffBits))*entW + (x >> uint(huffBits))
			grpIdx = int((entPixels[ei] >> 8) & 0xffff)
		}
		gt := &groups[grpIdx]
		sym, ok := gt.trees[0].readSymbol(r)
		if !ok {
			return nil, false
		}
		switch {
		case sym < 256:
			red, ok1 := gt.trees[1].readSymbol(r)
			blue, ok2 := gt.trees[2].readSymbol(r)
			alpha, ok3 := gt.trees[3].readSymbol(r)
			if !ok1 || !ok2 || !ok3 {
				return nil, false
			}
			if recordPixels {
				argb := (uint32(alpha) << 24) | (uint32(red) << 16) | (uint32(sym) << 8) | uint32(blue)
				pixels[pos] = argb
				if colorCacheSize > 0 {
					ccIdx := (argb * 0x1e35a7bd) >> uint(32-colorCacheBits)
					colorCache[ccIdx] = argb
				}
			}
			pos++
		case sym < 256+24:
			length, ok1 := vp8lPrefixValue(r, int(sym-256))
			if !ok1 || length <= 0 || pos+length > nPix {
				return nil, false
			}
			distSym, ok2 := gt.trees[4].readSymbol(r)
			if !ok2 {
				return nil, false
			}
			distCode, ok3 := vp8lPrefixValue(r, int(distSym))
			if !ok3 || distCode <= 0 {
				return nil, false
			}
			var dist int
			if distCode <= 120 {
				off := vp8lDistanceMap[distCode-1]
				dist = int(off[0]) + int(off[1])*codedW
				if dist < 1 {
					dist = 1
				}
			} else {
				dist = distCode - 120
			}
			if recordPixels {
				for k := 0; k < length; k++ {
					var argb uint32
					if dist <= pos {
						argb = pixels[pos-dist]
					}
					pixels[pos] = argb
					if colorCacheSize > 0 {
						ccIdx := (argb * 0x1e35a7bd) >> uint(32-colorCacheBits)
						colorCache[ccIdx] = argb
					}
					pos++
				}
			} else {
				pos += length
			}
		case int(sym) < 256+24+colorCacheSize:
			if recordPixels {
				argb := colorCache[int(sym)-256-24]
				pixels[pos] = argb
			}
			pos++
		default:
			return nil, false
		}
	}
	return pixels, true
}

func isValidVP8LStream(payload []byte) (int, int, bool) {
	if len(payload) < 5 || payload[0] != 0x2f {
		return 0, 0, false
	}
	bits := binary.LittleEndian.Uint32(payload[1:5])
	w := int(bits&0x3fff) + 1
	h := int((bits>>14)&0x3fff) + 1
	ver := (bits >> 29) & 7
	if ver != 0 {
		return 0, 0, false
	}
	r := vp8lBitReader{data: payload[5:]}
	if _, ok := decodeVP8LImageStream(&r, w, h, true, false, len(payload)-5); !ok {
		return 0, 0, false
	}
	if r.overread {
		return 0, 0, false
	}
	trailing := len(payload) - 5 - r.bytesUsed()
	if trailing < 0 || trailing > 2 {
		return 0, 0, false
	}
	return w, h, true
}

func isValidWebPALPHChunk(payload []byte, w, h int) bool {
	if len(payload) < 2 || w <= 0 || h <= 0 || int64(w)*int64(h) > 64_000_000 {
		return false
	}
	hdr := payload[0]
	reserved := (hdr >> 6) & 3
	compMethod := hdr & 3
	if reserved != 0 || compMethod > 1 {
		return false
	}
	if compMethod == 0 {
		raw := payload[1:]
		if len(raw) != w*h {
			return false
		}
		if (len(raw) >= 16 && hasHighPrintableAscii(raw)) || len(extractPrintableTextRuns(raw, 48)) > 0 {
			return false
		}
		if len(raw) >= minEntropyBytes {
			return hasRasterSpatialCorrelation(raw, w, h, 1, 8, false)
		}
		return true
	}
	r := vp8lBitReader{data: payload[1:]}
	if _, ok := decodeVP8LImageStream(&r, w, h, true, false, len(payload)-1); !ok {
		return false
	}
	if r.overread {
		return false
	}
	trailing := len(payload) - 1 - r.bytesUsed()
	return trailing >= 0 && trailing <= 2
}

type vp8BoolReader struct {
	data     []byte
	pos      int
	value    uint32
	rangeVal uint32
	bitCount int
	eofReads int
	err      bool
}

func newVP8BoolReader(data []byte) vp8BoolReader {
	r := vp8BoolReader{data: data, rangeVal: 255, bitCount: 8}
	if len(data) >= 2 {
		r.value = (uint32(data[0]) << 8) | uint32(data[1])
		r.pos = 2
	} else if len(data) == 1 {
		r.value = uint32(data[0]) << 8
		r.pos = 1
		r.eofReads = 1
	} else {
		r.err = true
	}
	return r
}

func (r *vp8BoolReader) readBit(prob uint8) uint32 {
	if r.err {
		return 0
	}
	split := 1 + (((r.rangeVal - 1) * uint32(prob)) >> 8)
	bigsplit := split << 8
	origRange := r.rangeVal
	r.rangeVal = split
	ret := uint32(0)
	if r.value >= bigsplit {
		r.rangeVal = origRange - split
		r.value -= bigsplit
		ret = 1
	}
	for r.rangeVal < 128 {
		r.rangeVal <<= 1
		r.value <<= 1
		r.bitCount--
		if r.bitCount == 0 {
			if r.pos < len(r.data) {
				r.value |= uint32(r.data[r.pos])
				r.pos++
			} else {
				r.eofReads++
				if r.eofReads > 3 {
					r.err = true
					return ret
				}
			}
			r.bitCount = 8
		}
	}
	return ret
}

func (r *vp8BoolReader) readLiteral(n int) uint32 {
	v := uint32(0)
	for i := 0; i < n; i++ {
		v = (v << 1) | r.readBit(128)
	}
	return v
}

func (r *vp8BoolReader) readSignedLiteral(n int) {
	r.readLiteral(n)
	r.readBit(128)
}

func (r *vp8BoolReader) readTree(tree, probs []int8) int {
	i := 0
	for {
		b := r.readBit(uint8(probs[i>>1]))
		next := int(tree[i+int(b)])
		if next <= 0 {
			return -next
		}
		i = next
	}
}

func (r *vp8BoolReader) readTreeU(tree []int8, probs []uint8) int {
	i := 0
	for {
		b := r.readBit(probs[i>>1])
		next := int(tree[i+int(b)])
		if next <= 0 {
			return -next
		}
		i = next
	}
}

var vp8KfYModeTree = []int8{-4, 2, 4, 6, 0, -1, -2, -3}
var vp8KfYModeProbs = []uint8{145, 156, 163, 128}
var vp8KfUVModeTree = []int8{0, 2, -1, 4, -2, -3}
var vp8KfUVModeProbs = []uint8{142, 114, 183}
var vp8KfBModeTree = []int8{
	0, 2,
	-1, 4,
	-2, 6,
	8, 12,
	-3, 10,
	-5, -6,
	-4, 14,
	-7, 16,
	-8, -9,
}

var vp8KfBModeProbs = [10][10][9]uint8{
	{
		{231, 120, 48, 89, 115, 113, 120, 152, 112},
		{152, 179, 64, 126, 170, 118, 46, 70, 95},
		{175, 69, 143, 80, 85, 82, 72, 155, 103},
		{56, 58, 10, 171, 218, 189, 17, 13, 152},
		{144, 71, 10, 38, 171, 213, 144, 34, 26},
		{114, 26, 17, 163, 44, 195, 21, 10, 173},
		{121, 24, 80, 195, 26, 62, 44, 64, 85},
		{170, 46, 55, 19, 136, 160, 33, 206, 71},
		{63, 20, 8, 114, 114, 208, 12, 9, 226},
		{81, 40, 11, 96, 182, 84, 29, 16, 36},
	},
	{
		{134, 183, 89, 137, 98, 101, 106, 165, 148},
		{72, 187, 100, 130, 157, 111, 32, 75, 80},
		{66, 102, 167, 99, 74, 62, 40, 234, 128},
		{41, 53, 9, 178, 241, 141, 26, 8, 107},
		{104, 79, 12, 27, 217, 255, 87, 17, 7},
		{74, 43, 26, 146, 73, 166, 49, 23, 157},
		{65, 38, 105, 160, 51, 52, 31, 115, 128},
		{87, 68, 71, 44, 114, 51, 15, 186, 23},
		{47, 41, 14, 110, 182, 183, 21, 17, 194},
		{66, 45, 25, 102, 197, 189, 23, 18, 22},
	},
	{
		{88, 88, 147, 150, 42, 46, 45, 196, 205},
		{43, 97, 183, 117, 85, 38, 35, 179, 61},
		{39, 53, 200, 87, 26, 21, 43, 232, 171},
		{56, 34, 51, 104, 114, 102, 29, 93, 77},
		{107, 54, 32, 26, 51, 1, 81, 43, 31},
		{39, 28, 85, 171, 58, 165, 90, 98, 64},
		{34, 22, 116, 206, 23, 34, 43, 166, 73},
		{68, 25, 106, 22, 64, 171, 36, 225, 114},
		{34, 19, 21, 102, 132, 188, 16, 76, 124},
		{62, 18, 78, 95, 85, 57, 50, 48, 51},
	},
	{
		{193, 101, 35, 159, 215, 111, 89, 46, 111},
		{60, 148, 31, 172, 219, 228, 21, 18, 111},
		{112, 113, 77, 85, 179, 255, 38, 120, 114},
		{40, 42, 1, 196, 245, 209, 10, 25, 109},
		{100, 80, 8, 43, 154, 1, 51, 26, 71},
		{88, 43, 29, 140, 166, 213, 37, 43, 154},
		{61, 63, 30, 155, 67, 45, 68, 1, 209},
		{142, 78, 78, 16, 255, 128, 34, 197, 171},
		{41, 40, 5, 102, 211, 183, 4, 1, 221},
		{51, 50, 17, 168, 209, 192, 23, 25, 82},
	},
	{
		{125, 98, 42, 88, 104, 85, 117, 175, 82},
		{95, 84, 53, 89, 128, 100, 113, 101, 45},
		{75, 79, 123, 47, 51, 128, 81, 171, 1},
		{57, 17, 5, 71, 102, 57, 53, 41, 49},
		{115, 21, 2, 10, 102, 255, 166, 23, 6},
		{38, 33, 13, 121, 57, 73, 26, 1, 85},
		{41, 10, 67, 138, 77, 110, 90, 47, 114},
		{101, 29, 16, 10, 85, 128, 101, 196, 26},
		{57, 18, 10, 102, 102, 213, 34, 20, 43},
		{117, 20, 15, 36, 163, 128, 68, 1, 26},
	},
	{
		{138, 31, 36, 171, 27, 166, 38, 44, 229},
		{67, 87, 58, 169, 82, 115, 26, 59, 179},
		{63, 59, 90, 180, 59, 166, 93, 73, 154},
		{40, 40, 21, 116, 143, 209, 34, 39, 175},
		{57, 46, 22, 24, 128, 1, 54, 17, 37},
		{47, 15, 16, 183, 34, 223, 49, 45, 183},
		{46, 17, 33, 183, 6, 98, 15, 32, 183},
		{65, 32, 73, 115, 28, 128, 23, 128, 205},
		{40, 3, 9, 115, 51, 192, 18, 6, 223},
		{87, 37, 9, 115, 59, 77, 64, 21, 47},
	},
	{
		{104, 55, 44, 218, 9, 54, 53, 130, 226},
		{64, 90, 70, 205, 40, 41, 23, 26, 57},
		{54, 57, 112, 184, 5, 41, 38, 166, 213},
		{30, 34, 26, 133, 152, 116, 10, 32, 134},
		{75, 32, 12, 51, 192, 255, 160, 43, 51},
		{39, 19, 53, 221, 26, 114, 32, 73, 255},
		{31, 9, 65, 234, 2, 15, 1, 118, 73},
		{88, 31, 35, 67, 102, 85, 55, 186, 85},
		{56, 21, 23, 111, 59, 205, 45, 37, 192},
		{55, 38, 70, 124, 73, 102, 1, 34, 98},
	},
	{
		{102, 61, 71, 37, 34, 53, 31, 243, 192},
		{69, 60, 71, 38, 73, 119, 28, 222, 37},
		{68, 45, 128, 34, 1, 47, 11, 245, 171},
		{62, 17, 19, 70, 146, 85, 55, 62, 70},
		{75, 15, 9, 9, 64, 255, 184, 119, 16},
		{37, 43, 37, 154, 100, 163, 85, 160, 1},
		{63, 9, 92, 136, 28, 64, 32, 201, 85},
		{86, 6, 28, 5, 64, 255, 25, 248, 1},
		{56, 8, 17, 132, 137, 255, 55, 116, 128},
		{58, 15, 20, 82, 135, 57, 26, 121, 40},
	},
	{
		{164, 50, 31, 137, 154, 133, 25, 35, 218},
		{51, 103, 44, 131, 131, 123, 31, 6, 158},
		{86, 40, 64, 135, 148, 224, 45, 183, 128},
		{22, 26, 17, 131, 240, 154, 14, 1, 209},
		{83, 12, 13, 54, 192, 255, 68, 47, 28},
		{45, 16, 21, 91, 64, 222, 7, 1, 197},
		{56, 21, 39, 155, 60, 138, 23, 102, 213},
		{85, 26, 85, 85, 128, 128, 32, 146, 171},
		{18, 11, 7, 63, 144, 171, 4, 4, 246},
		{35, 27, 10, 146, 174, 171, 12, 26, 128},
	},
	{
		{190, 80, 35, 99, 180, 80, 126, 54, 45},
		{85, 126, 47, 87, 176, 51, 41, 20, 32},
		{101, 75, 128, 139, 118, 146, 116, 128, 85},
		{56, 41, 15, 176, 236, 85, 37, 9, 62},
		{146, 36, 19, 30, 171, 255, 97, 27, 20},
		{71, 30, 17, 119, 118, 255, 17, 18, 138},
		{101, 38, 60, 138, 55, 70, 43, 26, 142},
		{138, 45, 61, 62, 219, 1, 81, 188, 64},
		{32, 41, 20, 117, 151, 142, 20, 21, 163},
		{112, 19, 12, 61, 195, 128, 48, 4, 24},
	},
}

var vp8CoeffUpdateProbs = [1056]uint8{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	176, 246, 255, 255, 255, 255, 255, 255, 255, 255, 255, 223, 241, 252, 255, 255, 255, 255, 255, 255, 255, 255, 249, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 244, 252, 255, 255, 255, 255, 255, 255, 255, 255, 234, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 246, 254, 255, 255, 255, 255, 255, 255, 255, 255, 239, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 248, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 254, 253, 255, 254, 255, 255, 255, 255, 255, 255, 250, 255, 254, 255, 254, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 225, 252, 241, 253, 255, 255, 254, 255, 255, 255, 255, 234, 250, 241, 250, 253, 255, 253, 254, 255, 255, 255,
	255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 223, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 238, 253, 254, 254, 255, 255, 255, 255, 255, 255, 255,
	255, 248, 254, 255, 255, 255, 255, 255, 255, 255, 255, 249, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 247, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255, 250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	186, 251, 250, 255, 255, 255, 255, 255, 255, 255, 255, 234, 251, 244, 254, 255, 255, 255, 255, 255, 255, 255, 251, 251, 243, 253, 254, 255, 254, 255, 255, 255, 255,
	255, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 236, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 251, 253, 253, 254, 254, 255, 255, 255, 255, 255, 255,
	255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 254, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	248, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250, 254, 252, 254, 255, 255, 255, 255, 255, 255, 255, 248, 254, 249, 253, 255, 255, 255, 255, 255, 255, 255,
	255, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255, 246, 253, 253, 255, 255, 255, 255, 255, 255, 255, 255, 252, 254, 251, 254, 254, 255, 255, 255, 255, 255, 255,
	255, 254, 252, 255, 255, 255, 255, 255, 255, 255, 255, 248, 254, 253, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 254, 254, 255, 255, 255, 255, 255, 255, 255,
	255, 251, 254, 255, 255, 255, 255, 255, 255, 255, 255, 245, 251, 254, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 251, 253, 255, 255, 255, 255, 255, 255, 255, 255, 252, 253, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 249, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

var vp8DefaultCoeffProbs = [1056]uint8{
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	253, 136, 254, 255, 228, 219, 128, 128, 128, 128, 128, 189, 129, 242, 255, 227, 213, 255, 219, 128, 128, 128, 106, 126, 227, 252, 214, 209, 255, 255, 128, 128, 128,
	1, 98, 248, 255, 236, 226, 255, 255, 128, 128, 128, 181, 133, 238, 254, 221, 234, 255, 154, 128, 128, 128, 78, 134, 202, 247, 198, 180, 255, 219, 128, 128, 128,
	1, 185, 249, 255, 243, 255, 128, 128, 128, 128, 128, 184, 150, 247, 255, 236, 224, 128, 128, 128, 128, 128, 77, 110, 216, 255, 236, 230, 128, 128, 128, 128, 128,
	1, 101, 251, 255, 241, 255, 128, 128, 128, 128, 128, 170, 139, 241, 252, 236, 209, 255, 255, 128, 128, 128, 37, 116, 196, 243, 228, 255, 255, 255, 128, 128, 128,
	1, 204, 254, 255, 245, 255, 128, 128, 128, 128, 128, 207, 160, 250, 255, 238, 128, 128, 128, 128, 128, 128, 102, 103, 231, 255, 211, 171, 128, 128, 128, 128, 128,
	1, 152, 252, 255, 240, 255, 128, 128, 128, 128, 128, 177, 135, 243, 255, 234, 225, 128, 128, 128, 128, 128, 80, 129, 211, 255, 194, 224, 128, 128, 128, 128, 128,
	1, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 246, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 255, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	198, 35, 237, 223, 193, 187, 162, 160, 145, 155, 62, 131, 45, 198, 221, 172, 176, 220, 157, 252, 221, 1, 68, 47, 146, 208, 149, 167, 221, 162, 255, 223, 128,
	1, 149, 241, 255, 221, 224, 255, 255, 128, 128, 128, 184, 141, 234, 253, 222, 220, 255, 199, 128, 128, 128, 81, 99, 181, 242, 176, 190, 249, 202, 255, 255, 128,
	1, 129, 232, 253, 214, 197, 242, 196, 255, 255, 128, 99, 121, 210, 250, 201, 198, 255, 202, 128, 128, 128, 23, 91, 163, 242, 170, 187, 247, 210, 255, 255, 128,
	1, 200, 246, 255, 234, 255, 128, 128, 128, 128, 128, 109, 178, 241, 255, 231, 245, 255, 255, 128, 128, 128, 44, 130, 201, 253, 205, 192, 255, 255, 128, 128, 128,
	1, 132, 239, 251, 219, 209, 255, 165, 128, 128, 128, 94, 136, 225, 251, 218, 190, 255, 255, 128, 128, 128, 22, 100, 174, 245, 186, 161, 255, 199, 128, 128, 128,
	1, 182, 249, 255, 232, 235, 128, 128, 128, 128, 128, 124, 143, 241, 255, 227, 234, 128, 128, 128, 128, 128, 35, 77, 181, 251, 193, 211, 255, 205, 128, 128, 128,
	1, 157, 247, 255, 236, 231, 255, 255, 128, 128, 128, 121, 141, 235, 255, 225, 227, 255, 255, 128, 128, 128, 45, 99, 188, 251, 195, 217, 255, 224, 128, 128, 128,
	1, 1, 251, 255, 213, 255, 128, 128, 128, 128, 128, 203, 1, 248, 255, 255, 128, 128, 128, 128, 128, 128, 137, 1, 177, 255, 224, 255, 128, 128, 128, 128, 128,
	253, 9, 248, 251, 207, 208, 255, 192, 128, 128, 128, 175, 13, 224, 243, 193, 185, 249, 198, 255, 255, 128, 73, 17, 171, 221, 161, 179, 236, 167, 255, 234, 128,
	1, 95, 247, 253, 212, 183, 255, 255, 128, 128, 128, 239, 90, 244, 250, 211, 209, 255, 255, 128, 128, 128, 155, 77, 195, 248, 188, 195, 255, 255, 128, 128, 128,
	1, 24, 239, 251, 218, 219, 255, 205, 128, 128, 128, 201, 51, 219, 255, 196, 186, 128, 128, 128, 128, 128, 69, 46, 190, 239, 201, 218, 255, 228, 128, 128, 128,
	1, 191, 251, 255, 255, 128, 128, 128, 128, 128, 128, 223, 165, 249, 255, 213, 255, 128, 128, 128, 128, 128, 141, 124, 248, 255, 255, 128, 128, 128, 128, 128, 128,
	1, 16, 248, 255, 255, 128, 128, 128, 128, 128, 128, 190, 36, 230, 255, 236, 255, 128, 128, 128, 128, 128, 149, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128,
	1, 226, 255, 128, 128, 128, 128, 128, 128, 128, 128, 247, 192, 255, 128, 128, 128, 128, 128, 128, 128, 128, 240, 128, 255, 128, 128, 128, 128, 128, 128, 128, 128,
	1, 134, 252, 255, 255, 128, 128, 128, 128, 128, 128, 213, 62, 250, 255, 255, 128, 128, 128, 128, 128, 128, 55, 93, 255, 128, 128, 128, 128, 128, 128, 128, 128,
	128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
	202, 24, 213, 235, 186, 191, 220, 160, 240, 175, 255, 126, 38, 182, 232, 169, 184, 228, 174, 255, 187, 128, 61, 46, 138, 219, 151, 178, 240, 170, 255, 216, 128,
	1, 112, 230, 250, 199, 191, 247, 159, 255, 255, 128, 166, 109, 228, 252, 211, 215, 255, 174, 128, 128, 128, 39, 77, 162, 232, 172, 180, 245, 178, 255, 255, 128,
	1, 52, 220, 246, 198, 199, 249, 220, 255, 255, 128, 124, 74, 191, 243, 183, 193, 250, 221, 255, 255, 128, 24, 71, 130, 219, 154, 170, 243, 182, 255, 255, 128,
	1, 182, 225, 249, 219, 240, 255, 224, 128, 128, 128, 149, 150, 226, 252, 216, 205, 255, 171, 128, 128, 128, 28, 108, 170, 242, 183, 194, 254, 223, 255, 255, 128,
	1, 81, 230, 252, 204, 203, 255, 192, 128, 128, 128, 123, 102, 209, 247, 188, 196, 255, 233, 128, 128, 128, 20, 95, 153, 243, 164, 173, 255, 203, 128, 128, 128,
	1, 222, 248, 255, 216, 213, 128, 128, 128, 128, 128, 168, 175, 246, 252, 235, 205, 255, 255, 128, 128, 128, 47, 116, 215, 255, 211, 212, 255, 255, 128, 128, 128,
	1, 121, 236, 253, 212, 214, 255, 255, 128, 128, 128, 141, 84, 213, 252, 201, 202, 255, 219, 128, 128, 128, 42, 80, 160, 240, 162, 185, 255, 205, 128, 128, 128,
	1, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 244, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128, 238, 1, 255, 128, 128, 128, 128, 128, 128, 128, 128,
}

var vp8CoeffBands = [16]int{0, 1, 2, 3, 6, 4, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7}
var vp8CoeffTree = []int8{
	0, 2,
	-1, 4,
	-2, 6,
	8, 12,
	-3, 10,
	-4, -5,
	14, 16,
	-6, -7,
	18, 20,
	-8, -9,
	-10, -11,
}
var vp8CoeffExtraProbs = [6][]uint8{
	{159},
	{165, 145},
	{173, 148, 140},
	{176, 155, 140, 135},
	{180, 157, 141, 134, 130},
	{254, 254, 243, 230, 196, 177, 153, 140, 133, 130, 129},
}

func validateVP8Partition1Tokens(
	partReaders []vp8BoolReader,
	coeffProbs *[1056]uint8,
	mbCols, mbRows int,
	yModes []uint8,
	mbSkips []bool,
) bool {
	decodeBlock := func(r *vp8BoolReader, plane, startIdx, ctxInit int) (int, bool) {
		prev := ctxInit
		node := 0
		nz := 0
		for i := startIdx; i < 16; i++ {
			band := vp8CoeffBands[i]
			base := ((plane*8+band)*3 + prev) * 11
			probs := coeffProbs[base : base+11]
			cur := node
			for {
				b := r.readBit(probs[cur>>1])
				next := int(vp8CoeffTree[cur+int(b)])
				if next <= 0 {
					cur = -next
					break
				}
				cur = next
			}
			if r.err {
				return 0, false
			}
			if cur == 0 { // EOB
				return nz, true
			}
			if cur == 1 { // ZERO
				prev = 0
				node = 2
				continue
			}
			nz = 1
			node = 0
			if cur == 2 {
				prev = 1
			} else {
				prev = 2
			}
			if cur >= 6 {
				ep := vp8CoeffExtraProbs[cur-6]
				for _, p := range ep {
					r.readBit(p)
				}
			}
			r.readBit(128) // sign bit
			if r.err {
				return 0, false
			}
		}
		return nz, true
	}

	numParts := len(partReaders)
	aboveY := make([]int, mbCols*4)
	aboveY2 := make([]int, mbCols)
	aboveU := make([]int, mbCols*2)
	aboveV := make([]int, mbCols*2)
	for my := 0; my < mbRows; my++ {
		r := &partReaders[my%numParts]
		var leftY [4]int
		var leftY2 int
		var leftU, leftV [2]int
		for mx := 0; mx < mbCols; mx++ {
			mbIdx := my*mbCols + mx
			yMode := yModes[mbIdx]
			if mbSkips[mbIdx] {
				for k := 0; k < 4; k++ {
					aboveY[mx*4+k] = 0
					leftY[k] = 0
				}
				for k := 0; k < 2; k++ {
					aboveU[mx*2+k] = 0
					leftU[k] = 0
					aboveV[mx*2+k] = 0
					leftV[k] = 0
				}
				if yMode != 4 {
					aboveY2[mx] = 0
					leftY2 = 0
				}
				continue
			}
			yPlane := 3
			yStart := 0
			if yMode != 4 {
				nz, ok := decodeBlock(r, 1, 0, aboveY2[mx]+leftY2)
				if !ok {
					return false
				}
				aboveY2[mx] = nz
				leftY2 = nz
				yPlane = 0
				yStart = 1
			}
			for r4 := 0; r4 < 4; r4++ {
				for c4 := 0; c4 < 4; c4++ {
					nz, ok := decodeBlock(r, yPlane, yStart, aboveY[mx*4+c4]+leftY[r4])
					if !ok {
						return false
					}
					aboveY[mx*4+c4] = nz
					leftY[r4] = nz
				}
			}
			for r2 := 0; r2 < 2; r2++ {
				for c2 := 0; c2 < 2; c2++ {
					nz, ok := decodeBlock(r, 2, 0, aboveU[mx*2+c2]+leftU[r2])
					if !ok {
						return false
					}
					aboveU[mx*2+c2] = nz
					leftU[r2] = nz
				}
			}
			for r2 := 0; r2 < 2; r2++ {
				for c2 := 0; c2 < 2; c2++ {
					nz, ok := decodeBlock(r, 2, 0, aboveV[mx*2+c2]+leftV[r2])
					if !ok {
						return false
					}
					aboveV[mx*2+c2] = nz
					leftV[r2] = nz
				}
			}
		}
	}
	for i := range partReaders {
		pr := &partReaders[i]
		if pr.err {
			return false
		}
		if len(pr.data)-pr.pos >= minEntropyBytes {
			return false
		}
	}
	return true
}

func isValidVP8Keyframe(payload []byte) (int, int, bool) {
	if len(payload) < 10 {
		return 0, 0, false
	}
	frameType := payload[0] & 0x01
	ver := (payload[0] >> 1) & 0x07
	firstPartSize := int(uint32(payload[0]>>5) | (uint32(payload[1]) << 3) | (uint32(payload[2]) << 11))
	if frameType != 0 || ver > 3 || firstPartSize <= 0 {
		return 0, 0, false
	}
	if payload[3] != 0x9d || payload[4] != 0x01 || payload[5] != 0x2a {
		return 0, 0, false
	}
	w := int(payload[6]) | (int(payload[7]&0x3f) << 8)
	h := int(payload[8]) | (int(payload[9]&0x3f) << 8)
	if w == 0 || h == 0 || int64(w)*int64(h) > 64_000_000 {
		return 0, 0, false
	}
	if 10+firstPartSize > len(payload) {
		return 0, 0, false
	}
	part0 := payload[10 : 10+firstPartSize]
	rest := payload[10+firstPartSize:]
	r := newVP8BoolReader(part0)

	_ = r.readBit(128) // color_space
	_ = r.readBit(128) // clamping_type
	segEnabled := r.readBit(128)
	updateSegMap := uint32(0)
	segTreeProbs := [3]uint8{255, 255, 255}
	if segEnabled == 1 {
		updateSegMap = r.readBit(128)
		updateSegData := r.readBit(128)
		if updateSegData == 1 {
			_ = r.readBit(128) // feature_data mode
			for i := 0; i < 4; i++ {
				if r.readBit(128) == 1 {
					r.readSignedLiteral(7)
				}
			}
			for i := 0; i < 4; i++ {
				if r.readBit(128) == 1 {
					r.readSignedLiteral(6)
				}
			}
		}
		if updateSegMap == 1 {
			for i := 0; i < 3; i++ {
				if r.readBit(128) == 1 {
					segTreeProbs[i] = uint8(r.readLiteral(8))
				}
			}
		}
	}
	_ = r.readBit(128)   // filter_type
	_ = r.readLiteral(6) // loop_filter_level
	_ = r.readLiteral(3) // sharpness_level
	lfAdj := r.readBit(128)
	if lfAdj == 1 {
		if r.readBit(128) == 1 {
			for i := 0; i < 4; i++ {
				if r.readBit(128) == 1 {
					r.readSignedLiteral(6)
				}
			}
			for i := 0; i < 4; i++ {
				if r.readBit(128) == 1 {
					r.readSignedLiteral(6)
				}
			}
		}
	}
	log2Parts := int(r.readLiteral(2))
	numParts := 1 << uint(log2Parts)
	if r.err {
		return 0, 0, false
	}
	offTableLen := (numParts - 1) * 3
	if len(rest) < offTableLen {
		return 0, 0, false
	}
	partSlices := make([][]byte, numParts)
	curPartOff := offTableLen
	for i := 0; i < numParts-1; i++ {
		sz := int(uint32(rest[i*3]) | (uint32(rest[i*3+1]) << 8) | (uint32(rest[i*3+2]) << 16))
		if sz <= 0 || curPartOff+sz > len(rest) {
			return 0, 0, false
		}
		partSlices[i] = rest[curPartOff : curPartOff+sz]
		curPartOff += sz
	}
	if curPartOff >= len(rest) {
		return 0, 0, false
	}
	partSlices[numParts-1] = rest[curPartOff:]

	_ = r.readLiteral(7) // y_ac_qi
	for i := 0; i < 5; i++ {
		if r.readBit(128) == 1 {
			r.readSignedLiteral(4)
		}
	}
	_ = r.readBit(128) // refresh_entropy_probs

	coeffProbs := vp8DefaultCoeffProbs
	for idx := 0; idx < 1056; idx++ {
		if r.readBit(vp8CoeffUpdateProbs[idx]) == 1 {
			coeffProbs[idx] = uint8(r.readLiteral(8))
		}
	}
	mbNoCoeffSkip := r.readBit(128)
	probSkipFalse := uint8(0)
	if mbNoCoeffSkip == 1 {
		probSkipFalse = uint8(r.readLiteral(8))
	}
	if r.err {
		return 0, 0, false
	}

	mbCols := (w + 15) / 16
	mbRows := (h + 15) / 16
	totalMBs := mbCols * mbRows
	if totalMBs <= 0 || totalMBs > 262144 {
		return 0, 0, false
	}
	aboveB := make([]int, mbCols*4)
	yModes := make([]uint8, totalMBs)
	mbSkips := make([]bool, totalMBs)
	mbsRead := 0
	for my := 0; my < mbRows; my++ {
		var leftB [4]int
		for mx := 0; mx < mbCols; mx++ {
			if segEnabled == 1 && updateSegMap == 1 {
				if r.readBit(segTreeProbs[0]) == 0 {
					_ = r.readBit(segTreeProbs[1])
				} else {
					_ = r.readBit(segTreeProbs[2])
				}
			}
			skip := false
			if mbNoCoeffSkip == 1 {
				skip = r.readBit(probSkipFalse) == 1
			}
			mbIdx := my*mbCols + mx
			mbSkips[mbIdx] = skip
			ym := r.readTreeU(vp8KfYModeTree, vp8KfYModeProbs)
			if r.err {
				break
			}
			yModes[mbIdx] = uint8(ym)
			if ym == 4 { // B_PRED
				for r4 := 0; r4 < 4; r4++ {
					for c4 := 0; c4 < 4; c4++ {
						am := aboveB[mx*4+c4]
						lm := leftB[r4]
						bm := r.readTreeU(vp8KfBModeTree, vp8KfBModeProbs[am][lm][:])
						if r.err {
							break
						}
						aboveB[mx*4+c4] = bm
						leftB[r4] = bm
					}
					if r.err {
						break
					}
				}
			} else {
				bm := 0
				switch ym {
				case 1: // V_PRED -> B_VE_PRED
					bm = 2
				case 2: // H_PRED -> B_HE_PRED
					bm = 3
				case 3: // TM_PRED -> B_TM_PRED
					bm = 1
				}
				for k := 0; k < 4; k++ {
					aboveB[mx*4+k] = bm
					leftB[k] = bm
				}
			}
			_ = r.readTreeU(vp8KfUVModeTree, vp8KfUVModeProbs)
			if r.err {
				break
			}
			mbsRead++
		}
		if r.err {
			break
		}
	}
	if r.err || mbsRead != totalMBs {
		return 0, 0, false
	}
	if len(part0) > 64 && r.pos*100 < len(part0)*35 {
		return 0, 0, false
	}
	if len(part0)-r.pos >= minEntropyBytes {
		return 0, 0, false
	}
	partReaders := make([]vp8BoolReader, numParts)
	for i, ps := range partSlices {
		partReaders[i] = newVP8BoolReader(ps)
	}
	if !validateVP8Partition1Tokens(partReaders, &coeffProbs, mbCols, mbRows, yModes, mbSkips) {
		return 0, 0, false
	}
	return w, h, true
}

func isWebPBitstreamPayloadValid(fourCC string, payload []byte) bool {
	if (len(payload) >= 16 && hasHighPrintableAscii(payload)) || len(extractPrintableTextRuns(payload, 48)) > 0 {
		return false
	}
	stripped := stripControlBytesForInspection(payload)
	if len(stripped) != len(payload) && ((len(stripped) >= 48 && hasHighPrintableAscii(stripped)) || len(extractPrintableTextRuns(stripped, 48)) > 0) {
		return false
	}
	switch fourCC {
	case "VP8 ":
		_, _, ok := isValidVP8Keyframe(payload)
		return ok
	case "VP8L":
		_, _, ok := isValidVP8LStream(payload)
		return ok
	default:
		return false
	}
}

func isValidWebPANMFChunk(payload []byte) bool {
	if len(payload) < 16 {
		return false
	}
	wMinus1 := uint32(payload[6]) | (uint32(payload[7]) << 8) | (uint32(payload[8]) << 16)
	hMinus1 := uint32(payload[9]) | (uint32(payload[10]) << 8) | (uint32(payload[11]) << 16)
	if wMinus1 == 0xffffff || hMinus1 == 0xffffff {
		return false
	}
	frameW := int(wMinus1) + 1
	frameH := int(hMinus1) + 1
	off := 16
	hasFrameImage := false
	var alphPayloads [][]byte
	for off < len(payload) {
		if off+8 > len(payload) {
			return false
		}
		subCC := string(payload[off : off+4])
		subSize := binary.LittleEndian.Uint32(payload[off+4 : off+8])
		if uint64(subSize) > uint64(len(payload)-off-8) {
			return false
		}
		subPayload := payload[off+8 : off+8+int(subSize)]
		switch subCC {
		case "VP8 ":
			w, h, ok := isValidVP8Keyframe(subPayload)
			if !ok || w != frameW || h != frameH {
				return false
			}
			hasFrameImage = true
		case "VP8L":
			w, h, ok := isValidVP8LStream(subPayload)
			if !ok || w != frameW || h != frameH {
				return false
			}
			hasFrameImage = true
		case "ALPH":
			alphPayloads = append(alphPayloads, subPayload)
		default:
			return false
		}
		paddedSize := int(subSize) + int(subSize&1)
		if off+8+paddedSize <= len(payload) {
			off += 8 + paddedSize
		} else if off+8+int(subSize) == len(payload) {
			off += 8 + int(subSize)
		} else {
			return false
		}
	}
	if off != len(payload) || !hasFrameImage {
		return false
	}
	for _, ap := range alphPayloads {
		if !isValidWebPALPHChunk(ap, frameW, frameH) {
			return false
		}
	}
	return true
}

func isValidWebPStructure(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	riffSize := binary.LittleEndian.Uint32(data[4:8])
	expectedLen := int64(riffSize) + 8
	actualLen := int64(len(data))
	if expectedLen < 20 || expectedLen < actualLen-1 || expectedLen > actualLen {
		return false
	}
	off := 12
	hasImageChunk := false
	imgW, imgH := 0, 0
	var alphPayloads [][]byte
	for off < int(expectedLen) {
		if off+8 > int(expectedLen) {
			return false
		}
		fourCC := string(data[off : off+4])
		chunkSize := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if uint64(chunkSize) > uint64(int(expectedLen)-off-8) {
			return false
		}
		payload := data[off+8 : off+8+int(chunkSize)]
		switch fourCC {
		case "VP8 ":
			w, h, ok := isValidVP8Keyframe(payload)
			if !ok {
				return false
			}
			imgW, imgH = w, h
			hasImageChunk = true
		case "VP8L":
			w, h, ok := isValidVP8LStream(payload)
			if !ok {
				return false
			}
			imgW, imgH = w, h
			hasImageChunk = true
		case "VP8X":
			if chunkSize != 10 {
				return false
			}
		case "ANIM":
			if chunkSize != 6 {
				return false
			}
		case "ANMF":
			if !isValidWebPANMFChunk(payload) {
				return false
			}
			hasImageChunk = true
		case "ALPH":
			alphPayloads = append(alphPayloads, payload)
		case "ICCP", "EXIF", "XMP ":
		default:
			return false
		}
		paddedSize := int(chunkSize) + int(chunkSize&1)
		if off+8+paddedSize <= int(expectedLen) {
			off += 8 + paddedSize
		} else if off+8+int(chunkSize) == int(expectedLen) {
			off += 8 + int(chunkSize)
		} else {
			return false
		}
	}
	if off != int(expectedLen) || !hasImageChunk {
		return false
	}
	for _, ap := range alphPayloads {
		if !isValidWebPALPHChunk(ap, imgW, imgH) {
			return false
		}
	}
	return true
}

func inspectWebPMetadataChunks(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if len(data) < 20 {
		return
	}
	riffSize := binary.LittleEndian.Uint32(data[4:8])
	expectedLen := int(min(int64(riffSize)+8, int64(len(data))))
	off := 12
	for off+8 <= expectedLen {
		fourCC := string(data[off : off+4])
		chunkSize := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if uint64(chunkSize) > uint64(expectedLen-off-8) {
			return
		}
		payload := data[off+8 : off+8+int(chunkSize)]
		switch fourCC {
		case "EXIF":
			inspectExifPayload(ctx, virtualPath, "#webp_exif", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		case "XMP ":
			inspectAncillaryPayload(ctx, virtualPath, "#webp_xmp", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
		case "ICCP":
			if isValidICCProfileHeaderAndTags(payload) {
				inspectValidatedICCProfile(ctx, virtualPath, "#webp_iccp", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			} else {
				inspectAncillaryPayload(ctx, virtualPath, "#webp_iccp", payload, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
		}
		paddedSize := int(chunkSize) + int(chunkSize&1)
		if off+8+paddedSize <= expectedLen {
			off += 8 + paddedSize
		} else {
			off += 8 + int(chunkSize)
		}
	}
}

var (
	pdfLengthDirectRe = regexp.MustCompile(`/Length\s+(\d+)\b`)
	pdfLengthRefRe    = regexp.MustCompile(`/Length\s+\d+\s+\d+\s+R\b`)
	pdfFilterBlockRe  = regexp.MustCompile(`/Filter\s*(?:\[([^\]]*)\]|/([^\s()<>[\]{}/%]+))`)
	pdfFilterNameRe   = regexp.MustCompile(`/([^\s()<>[\]{}/%]+)`)
	pdfWidthRe        = regexp.MustCompile(`/Width\s+(\d+)\b`)
	pdfHeightRe       = regexp.MustCompile(`/Height\s+(\d+)\b`)
	pdfBPCRe          = regexp.MustCompile(`/BitsPerComponent\s+(\d+)\b`)
	pdfPredictorRe    = regexp.MustCompile(`/Predictor\s+(\d+)\b`)
	pdfIndexedCSRe    = regexp.MustCompile(`/ColorSpace\s*\[\s*/Indexed\b`)
)

func isValidPDFHeaderSyntax(data []byte) bool {
	if !bytes.HasPrefix(data, []byte("%PDF-1.")) && !bytes.HasPrefix(data, []byte("%PDF-2.")) {
		return false
	}
	norm := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.IndexByte(norm, '\r') >= 0 {
		norm = bytes.ReplaceAll(norm, []byte("\r"), []byte("\n"))
	}
	if !pdfObjRe.Match(norm) || !pdfEndObjRe.Match(norm) || !pdfStartXrefRe.Match(norm) {
		return false
	}
	trimmed := bytes.TrimRight(norm, "\n \t\x00")
	lastLine := trimmed
	if nl := bytes.LastIndexByte(trimmed, '\n'); nl >= 0 {
		lastLine = trimmed[nl+1:]
	}
	return pdfEOFRe.Match(lastLine)
}

func isValidPDFStructure(data []byte) bool {
	if !isValidPDFHeaderSyntax(data) {
		return false
	}
	pdfRes := validateAndInspectPDFStreams(context.Background(), "", data, 0, 0, false, false, nil, nil, nil)
	return pdfRes.valid && !pdfRes.bombed
}

func isPDFDelimiterOrWS(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' ||
		b == '(' || b == ')' || b == '<' || b == '>' || b == '[' || b == ']' ||
		b == '{' || b == '}' || b == '/' || b == '%'
}

// findLastPDFObjHeaderEnd scans dictSlice skipping PDF comments (%...\n) and (...) literal strings
// (with nested parens and backslash escapes) and returns the index immediately after the last `\b\d+\s+\d+\s+obj\b`.
func findLastPDFObjHeaderEnd(b []byte) int {
	lastEnd := -1
	i := 0
	n := len(b)
	for i < n {
		switch b[i] {
		case '%':
			for i < n && b[i] != '\n' && b[i] != '\r' {
				i++
			}
		case '(':
			depth := 1
			i++
			for i < n && depth > 0 {
				if b[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if b[i] == '(' {
					depth++
				} else if b[i] == ')' {
					depth--
				}
				i++
			}
		default:
			if b[i] >= '0' && b[i] <= '9' && (i == 0 || isPDFDelimiterOrWS(b[i-1])) {
				p := i
				for p < n && b[p] >= '0' && b[p] <= '9' {
					p++
				}
				ws1 := p
				for p < n && (b[p] == ' ' || b[p] == '\t' || b[p] == '\r' || b[p] == '\n') {
					p++
				}
				if p > ws1 && p < n && b[p] >= '0' && b[p] <= '9' {
					for p < n && b[p] >= '0' && b[p] <= '9' {
						p++
					}
					ws2 := p
					for p < n && (b[p] == ' ' || b[p] == '\t' || b[p] == '\r' || b[p] == '\n') {
						p++
					}
					if p > ws2 && p+3 <= n && b[p] == 'o' && b[p+1] == 'b' && b[p+2] == 'j' {
						after := p + 3
						if after == n || isPDFDelimiterOrWS(b[after]) {
							lastEnd = after
							i = after
							continue
						}
					}
				}
			}
			i++
		}
	}
	return lastEnd
}

// stripPDFCommentsAndStrings strips %...\n comments and literal (...) string contents so dict regexes
// cannot be confused by comments between /Filter and its value or tokens inside /Producer (...) strings.
func stripPDFCommentsAndStrings(b []byte) []byte {
	out := make([]byte, 0, len(b))
	i := 0
	n := len(b)
	for i < n {
		switch b[i] {
		case '%':
			for i < n && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			out = append(out, ' ')
		case '(':
			depth := 1
			i++
			for i < n && depth > 0 {
				if b[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if b[i] == '(' {
					depth++
				} else if b[i] == ')' {
					depth--
				}
				i++
			}
			out = append(out, '(', ')')
		default:
			out = append(out, b[i])
			i++
		}
	}
	return out
}

func decodePDFName(raw string) (string, bool) {
	if !strings.ContainsRune(raw, '#') {
		return raw, true
	}
	var out strings.Builder
	out.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '#' {
			out.WriteByte(raw[i])
			continue
		}
		if i+2 >= len(raw) || !isHexByte(raw[i+1]) || !isHexByte(raw[i+2]) {
			return "", false
		}
		val, err := strconv.ParseUint(raw[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		out.WriteByte(byte(val))
		i += 2
	}
	return out.String(), true
}

func hasPDFDictKey(cleanDict []byte, key string) bool {
	needle := "/" + key
	idx := 0
	for idx < len(cleanDict) {
		rel := bytes.Index(cleanDict[idx:], []byte(needle))
		if rel < 0 {
			return false
		}
		end := idx + rel + len(needle)
		if end == len(cleanDict) || isPDFDelimiterOrWS(cleanDict[end]) {
			return true
		}
		idx = end
	}
	return false
}

func extractPDFDictNameAfterKey(cleanDict []byte, key string) (string, bool) {
	needle := "/" + key
	idx := 0
	for idx < len(cleanDict) {
		rel := bytes.Index(cleanDict[idx:], []byte(needle))
		if rel < 0 {
			return "", false
		}
		end := idx + rel + len(needle)
		if end < len(cleanDict) && isPDFDelimiterOrWS(cleanDict[end]) {
			p := end
			for p < len(cleanDict) && (cleanDict[p] == ' ' || cleanDict[p] == '\t' || cleanDict[p] == '\r' || cleanDict[p] == '\n') {
				p++
			}
			if p < len(cleanDict) && cleanDict[p] == '/' {
				p++
				start := p
				for p < len(cleanDict) && !isPDFDelimiterOrWS(cleanDict[p]) {
					p++
				}
				if decoded, ok := decodePDFName(string(cleanDict[start:p])); ok {
					return decoded, true
				}
			}
			return "", false
		}
		idx = end
	}
	return "", false
}

func hasPDFDictNameValue(cleanDict []byte, key string, allowed ...string) bool {
	val, ok := extractPDFDictNameAfterKey(cleanDict, key)
	if !ok {
		return false
	}
	for _, a := range allowed {
		if val == a {
			return true
		}
	}
	return false
}

func sfntChecksum(b []byte) uint32 {
	var sum uint32
	n := len(b)
	for i := 0; i+4 <= n; i += 4 {
		sum += binary.BigEndian.Uint32(b[i : i+4])
	}
	if rem := n % 4; rem > 0 {
		var tail [4]byte
		copy(tail[:], b[n-rem:])
		sum += binary.BigEndian.Uint32(tail[:])
	}
	return sum
}

func parseCFFIndex(b []byte, pos int) (items [][]byte, nextPos int, ok bool) {
	if pos < 0 || pos+2 > len(b) {
		return nil, 0, false
	}
	count := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	if count == 0 {
		return nil, pos + 2, true
	}
	if pos+3 > len(b) {
		return nil, 0, false
	}
	offSize := int(b[pos+2])
	if offSize < 1 || offSize > 4 {
		return nil, 0, false
	}
	offTableStart := pos + 3
	offTableBytes := (count + 1) * offSize
	if offTableStart+offTableBytes > len(b) {
		return nil, 0, false
	}
	readOff := func(idx int) int {
		p := offTableStart + idx*offSize
		v := 0
		for k := 0; k < offSize; k++ {
			v = (v << 8) | int(b[p+k])
		}
		return v
	}
	dataBase := offTableStart + offTableBytes - 1
	prevOff := readOff(0)
	if prevOff != 1 {
		return nil, 0, false
	}
	items = make([][]byte, 0, count)
	for i := 1; i <= count; i++ {
		curOff := readOff(i)
		if curOff < prevOff || dataBase+curOff > len(b) {
			return nil, 0, false
		}
		items = append(items, b[dataBase+prevOff:dataBase+curOff])
		prevOff = curOff
	}
	return items, dataBase + prevOff, true
}

func parseCFFDictEx(dict []byte) (charStringsOff, charsetOff, encodingOff, privateSize, privateOff, fdArrOff, fdSelOff, subrOff, vstoreOff int, ok bool) {
	var stack []int
	pos := 0
	for pos < len(dict) {
		b0 := dict[pos]
		switch {
		case b0 == 28:
			if pos+3 > len(dict) {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			v := int(int16(binary.BigEndian.Uint16(dict[pos+1 : pos+3])))
			stack = append(stack, v)
			pos += 3
		case b0 == 29:
			if pos+5 > len(dict) {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			v := int(int32(binary.BigEndian.Uint32(dict[pos+1 : pos+5])))
			stack = append(stack, v)
			pos += 5
		case b0 == 30:
			pos++
			done := false
			for pos < len(dict) {
				nb := dict[pos]
				pos++
				if (nb>>4) == 0x0f || (nb&0x0f) == 0x0f {
					done = true
					break
				}
			}
			if !done {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			stack = append(stack, 0)
		case b0 >= 32 && b0 <= 246:
			stack = append(stack, int(b0)-139)
			pos++
		case b0 >= 247 && b0 <= 250:
			if pos+2 > len(dict) {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			stack = append(stack, (int(b0)-247)*256+int(dict[pos+1])+108)
			pos += 2
		case b0 >= 251 && b0 <= 254:
			if pos+2 > len(dict) {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			stack = append(stack, -(int(b0)-251)*256-int(dict[pos+1])-108)
			pos += 2
		case b0 == 12:
			if pos+2 > len(dict) {
				return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
			}
			op2 := dict[pos+1]
			if op2 == 36 && len(stack) >= 1 {
				fdArrOff = stack[len(stack)-1]
			} else if op2 == 37 && len(stack) >= 1 {
				fdSelOff = stack[len(stack)-1]
			}
			stack = stack[:0]
			pos += 2
		case b0 <= 25:
			op := int(b0)
			switch op {
			case 15:
				if len(stack) >= 1 {
					charsetOff = stack[len(stack)-1]
				}
			case 16:
				if len(stack) >= 1 {
					encodingOff = stack[len(stack)-1]
				}
			case 17:
				if len(stack) >= 1 {
					charStringsOff = stack[len(stack)-1]
				}
			case 18:
				if len(stack) >= 2 {
					privateSize = stack[len(stack)-2]
					privateOff = stack[len(stack)-1]
				}
			case 19:
				if len(stack) >= 1 {
					subrOff = stack[len(stack)-1]
				}
			case 24:
				if len(stack) >= 1 {
					vstoreOff = stack[len(stack)-1]
				}
			}
			stack = stack[:0]
			pos++
		default:
			return 0, 0, 0, 0, 0, 0, 0, 0, 0, false
		}
	}
	return charStringsOff, charsetOff, encodingOff, privateSize, privateOff, fdArrOff, fdSelOff, subrOff, vstoreOff, true
}

type byteSpan struct {
	start int
	end   int
}

func checkGapsEntropy(b []byte, spans []byteSpan, startAt, endAt int) bool {
	if startAt < 0 {
		startAt = 0
	}
	if endAt > len(b) {
		endAt = len(b)
	}
	if startAt >= endAt {
		return true
	}
	checkGapSlice := func(gap []byte) bool {
		if len(gap) < minEntropyBytes {
			return true
		}
		return !hasConcealedHighEntropy(gap)
	}
	if len(spans) == 0 {
		return checkGapSlice(b[startAt:endAt])
	}
	sorted := make([]byteSpan, len(spans))
	copy(sorted, spans)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].start != sorted[j].start {
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].end < sorted[j].end
	})
	cur := startAt
	for _, sp := range sorted {
		if cur >= endAt {
			break
		}
		if sp.start > cur {
			if !checkGapSlice(b[cur:min(sp.start, endAt)]) {
				return false
			}
		}
		if sp.end > cur {
			cur = sp.end
		}
	}
	if cur < endAt {
		if !checkGapSlice(b[cur:endAt]) {
			return false
		}
	}
	return true
}

func cffSubrBias(n int) int {
	if n < 1240 {
		return 107
	}
	if n < 33900 {
		return 1131
	}
	return 32768
}

func isValidType2Esc(esc byte) bool {
	switch esc {
	case 3, 4, 5, 9, 10, 11, 12, 14, 15, 18, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30, 34, 35, 36, 37:
		return true
	default:
		return false
	}
}

type t2ExecCtx struct {
	gsubs        [][]byte
	gsubUsed     []bool
	lsubs        [][]byte
	lsubUsed     []bool
	isCFF2       bool
	regionCounts []int
	vsIndex      int
	stems        int
	hadWidth     bool
	steps        int
	maxSteps     int
	transient    [32]int
	stack        []int
}

func (c *t2ExecCtx) maxStack() int {
	if c.isCFF2 {
		return 513
	}
	return 48
}

func (c *t2ExecCtx) push(v int) bool {
	if len(c.stack) >= c.maxStack() {
		return false
	}
	c.stack = append(c.stack, v)
	return true
}

func (c *t2ExecCtx) exec(cs []byte, depth int) (ended bool, ok bool) {
	if depth > 12 {
		return false, false
	}
	p := 0
	for p < len(cs) {
		c.steps++
		if c.steps > c.maxSteps {
			return false, false
		}
		v := cs[p]
		switch {
		case v >= 32 && v <= 246:
			if !c.push(int(v) - 139) {
				return false, false
			}
			p++
		case v >= 247 && v <= 250:
			if p+2 > len(cs) {
				return false, false
			}
			if !c.push((int(v)-247)*256 + int(cs[p+1]) + 108) {
				return false, false
			}
			p += 2
		case v >= 251 && v <= 254:
			if p+2 > len(cs) {
				return false, false
			}
			if !c.push(-(int(v)-251)*256 - int(cs[p+1]) - 108) {
				return false, false
			}
			p += 2
		case v == 28:
			if p+3 > len(cs) {
				return false, false
			}
			if !c.push(int(int16(binary.BigEndian.Uint16(cs[p+1 : p+3])))) {
				return false, false
			}
			p += 3
		case v == 255:
			if p+5 > len(cs) {
				return false, false
			}
			if !c.push(int(int32(binary.BigEndian.Uint32(cs[p+1 : p+5])))) {
				return false, false
			}
			p += 5
		case v == 12:
			if p+2 > len(cs) {
				return false, false
			}
			esc := cs[p+1]
			if !isValidType2Esc(esc) {
				return false, false
			}
			p += 2
			switch esc {
			case 3, 4, 10, 11, 12, 15, 24: // binary op
				if len(c.stack) < 2 {
					return false, false
				}
				a, b := c.stack[len(c.stack)-2], c.stack[len(c.stack)-1]
				c.stack = c.stack[:len(c.stack)-1]
				switch esc {
				case 10:
					c.stack[len(c.stack)-1] = a + b
				case 11:
					c.stack[len(c.stack)-1] = a - b
				case 24:
					c.stack[len(c.stack)-1] = a * b
				case 12:
					if b != 0 {
						c.stack[len(c.stack)-1] = a / b
					} else {
						c.stack[len(c.stack)-1] = 0
					}
				case 15:
					if a == b {
						c.stack[len(c.stack)-1] = 1
					} else {
						c.stack[len(c.stack)-1] = 0
					}
				default:
					c.stack[len(c.stack)-1] = 0
				}
			case 5, 9, 14, 26: // unary op
				if len(c.stack) < 1 {
					return false, false
				}
				top := c.stack[len(c.stack)-1]
				if esc == 9 && top < 0 {
					c.stack[len(c.stack)-1] = -top
				} else if esc == 14 {
					c.stack[len(c.stack)-1] = -top
				}
			case 18: // drop
				if len(c.stack) < 1 {
					return false, false
				}
				c.stack = c.stack[:len(c.stack)-1]
			case 20: // put
				if len(c.stack) < 2 {
					return false, false
				}
				val, idx := c.stack[len(c.stack)-2], c.stack[len(c.stack)-1]
				c.stack = c.stack[:len(c.stack)-2]
				if idx >= 0 && idx < len(c.transient) {
					c.transient[idx] = val
				}
			case 21: // get
				if len(c.stack) < 1 {
					return false, false
				}
				idx := c.stack[len(c.stack)-1]
				if idx >= 0 && idx < len(c.transient) {
					c.stack[len(c.stack)-1] = c.transient[idx]
				} else {
					c.stack[len(c.stack)-1] = 0
				}
			case 22: // ifelse
				if len(c.stack) < 4 {
					return false, false
				}
				s1, s2, v1, v2 := c.stack[len(c.stack)-4], c.stack[len(c.stack)-3], c.stack[len(c.stack)-2], c.stack[len(c.stack)-1]
				c.stack = c.stack[:len(c.stack)-3]
				if v1 <= v2 {
					c.stack[len(c.stack)-1] = s1
				} else {
					c.stack[len(c.stack)-1] = s2
				}
			case 23: // random
				if !c.push(1) {
					return false, false
				}
			case 27: // dup
				if len(c.stack) < 1 {
					return false, false
				}
				if !c.push(c.stack[len(c.stack)-1]) {
					return false, false
				}
			case 28: // exch
				if len(c.stack) < 2 {
					return false, false
				}
				n := len(c.stack)
				c.stack[n-1], c.stack[n-2] = c.stack[n-2], c.stack[n-1]
			case 29: // index
				if len(c.stack) < 1 {
					return false, false
				}
				idx := c.stack[len(c.stack)-1]
				c.stack = c.stack[:len(c.stack)-1]
				if len(c.stack) == 0 {
					return false, false
				}
				if idx < 0 {
					idx = 0
				}
				if idx >= len(c.stack) {
					idx = len(c.stack) - 1
				}
				if !c.push(c.stack[len(c.stack)-1-idx]) {
					return false, false
				}
			case 30: // roll
				if len(c.stack) < 2 {
					return false, false
				}
				nCnt := c.stack[len(c.stack)-2]
				jAmt := c.stack[len(c.stack)-1]
				c.stack = c.stack[:len(c.stack)-2]
				if nCnt > 0 && nCnt <= len(c.stack) {
					jAmt %= nCnt
					if jAmt < 0 {
						jAmt += nCnt
					}
					if jAmt > 0 {
						sub := c.stack[len(c.stack)-nCnt:]
						tmp := append([]int(nil), sub...)
						for k := 0; k < nCnt; k++ {
							sub[(k+jAmt)%nCnt] = tmp[k]
						}
					}
				}
			case 34, 35, 36, 37: // flex ops
				c.stack = c.stack[:0]
			}
		case v == 1 || v == 3 || v == 18 || v == 23: // stems
			if !c.isCFF2 && !c.hadWidth && len(c.stack)%2 == 1 {
				c.hadWidth = true
			}
			c.stems += len(c.stack) / 2
			c.stack = c.stack[:0]
			p++
		case v == 19 || v == 20: // hintmask / cntrmask
			if !c.isCFF2 && !c.hadWidth && len(c.stack)%2 == 1 {
				c.hadWidth = true
			}
			c.stems += len(c.stack) / 2
			c.stack = c.stack[:0]
			maskBytes := (c.stems + 7) / 8
			p += 1 + maskBytes
			if p > len(cs) {
				return false, false
			}
		case v == 10: // callsubr
			if len(c.stack) < 1 || len(c.lsubs) == 0 {
				return false, false
			}
			opVal := c.stack[len(c.stack)-1]
			c.stack = c.stack[:len(c.stack)-1]
			idx := opVal + cffSubrBias(len(c.lsubs))
			if idx < 0 || idx >= len(c.lsubs) {
				return false, false
			}
			if idx < len(c.lsubUsed) {
				c.lsubUsed[idx] = true
			}
			p++
			subEnded, subOK := c.exec(c.lsubs[idx], depth+1)
			if !subOK {
				return false, false
			}
			if subEnded {
				return true, true
			}
		case v == 29: // callgsubr
			if len(c.stack) < 1 || len(c.gsubs) == 0 {
				return false, false
			}
			opVal := c.stack[len(c.stack)-1]
			c.stack = c.stack[:len(c.stack)-1]
			idx := opVal + cffSubrBias(len(c.gsubs))
			if idx < 0 || idx >= len(c.gsubs) {
				return false, false
			}
			if idx < len(c.gsubUsed) {
				c.gsubUsed[idx] = true
			}
			p++
			subEnded, subOK := c.exec(c.gsubs[idx], depth+1)
			if !subOK {
				return false, false
			}
			if subEnded {
				return true, true
			}
		case v == 11: // return
			if depth == 0 {
				return false, false
			}
			return false, true
		case v == 14: // endchar
			if c.isCFF2 {
				return false, false
			}
			c.stack = c.stack[:0]
			return true, true
		case v == 15 && c.isCFF2: // vsindex
			if len(c.stack) < 1 {
				return false, false
			}
			c.vsIndex = c.stack[len(c.stack)-1]
			c.stack = c.stack[:len(c.stack)-1]
			p++
		case v == 16 && c.isCFF2: // blend
			if len(c.stack) < 1 {
				return false, false
			}
			nVals := c.stack[len(c.stack)-1]
			c.stack = c.stack[:len(c.stack)-1]
			nReg := 0
			if c.vsIndex >= 0 && c.vsIndex < len(c.regionCounts) {
				nReg = c.regionCounts[c.vsIndex]
			}
			popCnt := nVals * nReg
			if nVals < 0 || popCnt < 0 || popCnt > len(c.stack) {
				return false, false
			}
			c.stack = c.stack[:len(c.stack)-popCnt]
			p++
		case v == 4 || v == 21 || v == 22: // moveto
			if !c.isCFF2 {
				c.hadWidth = true
			}
			c.stack = c.stack[:0]
			p++
		case v == 5 || v == 6 || v == 7 || v == 8 || v == 24 || v == 25 || v == 26 || v == 27 || v == 30 || v == 31:
			c.stack = c.stack[:0]
			p++
		default:
			return false, false
		}
	}
	if c.isCFF2 {
		return depth == 0, true
	}
	return false, false
}

func validateUncalledSubr(subr []byte, isCFF2 bool) bool {
	if len(subr) == 0 {
		return true
	}
	p := 0
	var lastOp byte
	hasMask := false
	for p < len(subr) {
		v := subr[p]
		switch {
		case v >= 32 && v <= 246:
			p++
		case v >= 247 && v <= 254:
			if p+2 > len(subr) {
				return false
			}
			p += 2
		case v == 28:
			if p+3 > len(subr) {
				return false
			}
			p += 3
		case v == 255:
			if p+5 > len(subr) {
				return false
			}
			p += 5
		case v == 12:
			if p+2 > len(subr) || !isValidType2Esc(subr[p+1]) {
				return false
			}
			lastOp = v
			p += 2
		case v == 19 || v == 20:
			hasMask = true
			p = len(subr)
		case v == 1 || v == 3 || v == 4 || v == 5 || v == 6 || v == 7 || v == 8 ||
			v == 10 || v == 11 || v == 18 || v == 21 || v == 22 || v == 23 ||
			v == 24 || v == 25 || v == 26 || v == 27 || v == 29 || v == 30 || v == 31:
			lastOp = v
			p++
		case v == 14 && !isCFF2:
			lastOp = v
			p++
		case (v == 15 || v == 16) && isCFF2:
			lastOp = v
			p++
		default:
			return false
		}
	}
	if hasMask || len(subr) >= minEntropyBytes {
		if hasConcealedHighEntropyThresh(subr, 7.80) {
			return false
		}
	}
	if hasMask {
		return true
	}
	if isCFF2 {
		return true
	}
	return lastOp == 11 || lastOp == 14 || lastOp == 10 || lastOp == 29
}

func validateCFFCodeIndexItems(items [][]byte) bool {
	var aggSmall []byte
	var ffPayloads []byte
	var run12 []byte
	var imm28 []byte
	var imm247 []byte
	var imm247Plus28 []byte
	var op1Bs []byte
	var idx1B, idx2B, idx3B int
	var op1BCounts [256]int
	for _, item := range items {
		if len(item) >= minEntropyBytes {
			if hasConcealedHighEntropyThresh(item, 7.50) {
				return false
			}
		} else if len(item) > 0 {
			aggSmall = append(aggSmall, item...)
		}
		p := 0
		runStart := -1
		for p < len(item) {
			v := item[p]
			if v >= 32 && v <= 246 {
				if runStart < 0 {
					runStart = p
				}
				idx1B++
				op1BCounts[v]++
				op1Bs = append(op1Bs, v)
				p++
				continue
			}
			if runStart >= 0 {
				if p-runStart >= 12 {
					run12 = append(run12, item[runStart:p]...)
				}
				runStart = -1
			}
			switch {
			case v >= 247 && v <= 254:
				if p+2 > len(item) {
					p = len(item)
					break
				}
				imm247 = append(imm247, item[p+1])
				imm247Plus28 = append(imm247Plus28, item[p+1])
				idx2B++
				p += 2
			case v == 28:
				if p+3 > len(item) {
					p = len(item)
					break
				}
				imm28 = append(imm28, item[p+1:p+3]...)
				imm247Plus28 = append(imm247Plus28, item[p+1:p+3]...)
				idx3B++
				p += 3
			case v == 255:
				if p+5 <= len(item) {
					ffPayloads = append(ffPayloads, item[p+1:p+5]...)
					p += 5
				} else {
					p = len(item)
				}
			case v == 12:
				if p+2 <= len(item) {
					p += 2
				} else {
					p = len(item)
				}
			default:
				p++
			}
		}
		if runStart >= 0 && p-runStart >= 12 {
			run12 = append(run12, item[runStart:p]...)
		}
	}
	if len(aggSmall) >= minEntropyBytes && hasConcealedHighEntropyThresh(aggSmall, 7.65) {
		return false
	}
	if len(ffPayloads) >= minEntropyBytes && hasConcealedHighEntropy(ffPayloads) {
		return false
	}
	if len(run12) >= minEntropyBytes && hasConcealedHighEntropyThresh(run12, 7.58) {
		return false
	}
	if len(imm28) >= minEntropyBytes {
		if _, highEnt := checkHighEntropyThresh(imm28, 7.00); highEnt {
			return false
		}
		if checkMaxEntWindowIncompressible(imm28, 6.85) {
			return false
		}
	}
	totOps := idx1B + idx2B + idx3B
	sumConst := 0
	for v := 32; v <= 246; v++ {
		if op1BCounts[v]*100 > totOps*3 {
			sumConst += op1BCounts[v]
		}
	}
	if len(op1Bs) >= 128 {
		d1b := distinctBytesCount(op1Bs)
		ent1B, _ := shannonEntropyAndPrintable(op1Bs)
		if d1b <= 80 || ent1B < 5.60 {
			sumConst = idx1B
		}
	}
	totNonConstOps := max(1, totOps-sumConst)
	cffImmConcealed := func(imm []byte) bool {
		if len(imm) >= 512 {
			return hasConcealedHighEntropyThresh(imm, 7.00) ||
				hasBitAgnosticIncompressible(imm, 5.80, 0.80)
		}
		return hasConcealedHighEntropyThresh(imm, 7.35) ||
			checkMaxEntWindowIncompressible(imm, 7.00) ||
			hasBitAgnosticIncompressible(imm, 6.40, 0.85)
	}
	if idx2B >= 128 && idx2B*100 > totNonConstOps*62 && cffImmConcealed(imm247) {
		return false
	}
	if len(imm247) >= minEntropyBytes && zlibCompressedRatio(imm247) >= 0.95 && hasConcealedHighEntropyThresh(imm247, 7.90) {
		return false
	}
	if (idx2B+idx3B) >= 128 && (idx2B+idx3B)*100 > totNonConstOps*62 && cffImmConcealed(imm247Plus28) {
		return false
	}
	return true
}

func parseCFFFDSelect(b []byte, fdSelOff, numGlyphs int) (fdMap []int, endOff int, ok bool) {
	if fdSelOff <= 0 || fdSelOff >= len(b) || numGlyphs <= 0 {
		return nil, 0, false
	}
	fmtByte := b[fdSelOff]
	switch fmtByte {
	case 0:
		end := fdSelOff + 1 + numGlyphs
		if end > len(b) {
			return nil, 0, false
		}
		fdMap = make([]int, numGlyphs)
		for i := 0; i < numGlyphs; i++ {
			fdMap[i] = int(b[fdSelOff+1+i])
		}
		return fdMap, end, true
	case 3:
		if fdSelOff+3 > len(b) {
			return nil, 0, false
		}
		nRanges := int(binary.BigEndian.Uint16(b[fdSelOff+1 : fdSelOff+3]))
		end := fdSelOff + 3 + nRanges*3 + 2
		if end > len(b) || nRanges == 0 {
			return nil, 0, false
		}
		fdMap = make([]int, numGlyphs)
		prevNextFirst := 0
		for i := 0; i < nRanges; i++ {
			recOff := fdSelOff + 3 + i*3
			first := int(binary.BigEndian.Uint16(b[recOff : recOff+2]))
			fd := int(b[recOff+2])
			nextFirst := int(binary.BigEndian.Uint16(b[recOff+3 : recOff+5]))
			if first < prevNextFirst || first > nextFirst || nextFirst > numGlyphs {
				return nil, 0, false
			}
			prevNextFirst = nextFirst
			for g := first; g < nextFirst; g++ {
				fdMap[g] = fd
			}
		}
		return fdMap, end, true
	case 4:
		if fdSelOff+5 > len(b) {
			return nil, 0, false
		}
		nRanges := int(binary.BigEndian.Uint32(b[fdSelOff+1 : fdSelOff+5]))
		end := fdSelOff + 5 + nRanges*6 + 4
		if end > len(b) || nRanges == 0 {
			return nil, 0, false
		}
		fdMap = make([]int, numGlyphs)
		prevNextFirst := 0
		for i := 0; i < nRanges; i++ {
			recOff := fdSelOff + 5 + i*6
			first := int(binary.BigEndian.Uint32(b[recOff : recOff+4]))
			fd := int(binary.BigEndian.Uint16(b[recOff+4 : recOff+6]))
			nextFirst := int(binary.BigEndian.Uint32(b[recOff+6 : recOff+10]))
			if first < prevNextFirst || first > nextFirst || nextFirst > numGlyphs {
				return nil, 0, false
			}
			prevNextFirst = nextFirst
			for g := first; g < nextFirst; g++ {
				fdMap[g] = fd
			}
		}
		return fdMap, end, true
	default:
		return nil, 0, false
	}
}

func isValidCFFFont(b []byte) bool {
	if len(b) < 4 || b[0] != 1 || b[1] != 0 || b[2] < 4 || int(b[2]) > len(b) || b[3] < 1 || b[3] > 4 {
		return false
	}
	names, nameEnd, ok := parseCFFIndex(b, int(b[2]))
	if !ok || len(names) == 0 {
		return false
	}
	for _, nm := range names {
		if len(nm) == 0 {
			return false
		}
		for _, ch := range nm {
			if ch < 0x20 || ch > 0x7e {
				return false
			}
		}
	}
	topDicts, topDictEnd, ok := parseCFFIndex(b, nameEnd)
	if !ok || len(topDicts) != len(names) {
		return false
	}
	if _, highEnt := checkHighEntropy(b[nameEnd:topDictEnd]); highEnt {
		return false
	}
	strItems, strEnd, ok := parseCFFIndex(b, topDictEnd) // String INDEX
	if !ok {
		return false
	}
	for _, s := range strItems {
		if !utf8.Valid(s) {
			return false
		}
		for _, r := range string(s) {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	gsubItems, globalSubrEnd, ok := parseCFFIndex(b, strEnd) // Global Subr INDEX
	if !ok || !validateCFFCodeIndexItems(gsubItems) {
		return false
	}

	covered := []byteSpan{{start: 0, end: globalSubrEnd}}
	maxEnd := globalSubrEnd
	gsubUsed := make([]bool, len(gsubItems))
	var aggUncalledSubrs []byte
	totalSteps := 0
	for _, td := range topDicts {
		csOff, charsetOff, encodingOff, privSize, privOff, fdArrOff, fdSelOff, _, _, dok := parseCFFDictEx(td)
		if !dok || csOff <= 0 || csOff >= len(b) {
			return false
		}
		csItems, csEnd, ok := parseCFFIndex(b, csOff)
		if !ok || len(csItems) == 0 || !validateCFFCodeIndexItems(csItems) {
			return false
		}
		numGlyphs := len(csItems)
		covered = append(covered, byteSpan{start: csOff, end: csEnd})
		if csEnd > maxEnd {
			maxEnd = csEnd
		}
		if charsetOff > 2 {
			if charsetOff >= len(b) {
				return false
			}
			rem := numGlyphs - 1
			p := charsetOff + 1
			switch b[charsetOff] {
			case 0:
				p += rem * 2
				rem = 0
			case 1:
				for rem > 0 {
					if p+3 > len(b) {
						return false
					}
					nLeft := int(b[p+2])
					p += 3
					rem -= 1 + nLeft
				}
			case 2:
				for rem > 0 {
					if p+4 > len(b) {
						return false
					}
					nLeft := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
					p += 4
					rem -= 1 + nLeft
				}
			default:
				return false
			}
			if rem != 0 || p > len(b) {
				return false
			}
			covered = append(covered, byteSpan{start: charsetOff, end: p})
			if p > maxEnd {
				maxEnd = p
			}
		}
		if encodingOff > 1 {
			if encodingOff >= len(b) {
				return false
			}
			fmtByte := b[encodingOff]
			baseFmt := fmtByte & 0x7f
			hasSupp := (fmtByte & 0x80) != 0
			p := encodingOff + 1
			switch baseFmt {
			case 0:
				if p >= len(b) {
					return false
				}
				p += 1 + int(b[p])
			case 1:
				if p >= len(b) {
					return false
				}
				p += 1 + int(b[p])*2
			default:
				return false
			}
			if hasSupp {
				if p >= len(b) {
					return false
				}
				p += 1 + int(b[p])*3
			}
			if p > len(b) {
				return false
			}
			covered = append(covered, byteSpan{start: encodingOff, end: p})
			if p > maxEnd {
				maxEnd = p
			}
		}
		var fdMap []int
		if fdSelOff > 0 {
			var fdSelEnd int
			var fsOK bool
			fdMap, fdSelEnd, fsOK = parseCFFFDSelect(b, fdSelOff, numGlyphs)
			if !fsOK {
				return false
			}
			covered = append(covered, byteSpan{start: fdSelOff, end: fdSelEnd})
			if fdSelEnd > maxEnd {
				maxEnd = fdSelEnd
			}
		}
		type fdSubrs struct {
			items [][]byte
			used  []bool
		}
		var fdLocalSubrs []fdSubrs
		if fdArrOff > 0 {
			fdItems, fdArrEnd, fok := parseCFFIndex(b, fdArrOff)
			if !fok || len(fdItems) == 0 {
				return false
			}
			if _, highEnt := checkHighEntropy(b[fdArrOff:fdArrEnd]); highEnt {
				return false
			}
			covered = append(covered, byteSpan{start: fdArrOff, end: fdArrEnd})
			if fdArrEnd > maxEnd {
				maxEnd = fdArrEnd
			}
			fdLocalSubrs = make([]fdSubrs, len(fdItems))
			for fi, fdDict := range fdItems {
				_, _, _, fPrivSz, fPrivOff, _, _, _, _, fOK := parseCFFDictEx(fdDict)
				if !fOK {
					return false
				}
				if fPrivSz > 0 {
					if fPrivOff < 0 || uint64(fPrivOff)+uint64(fPrivSz) > uint64(len(b)) {
						return false
					}
					fPrivSlice := b[fPrivOff : fPrivOff+fPrivSz]
					if hasConcealedHighEntropy(fPrivSlice) {
						return false
					}
					covered = append(covered, byteSpan{start: fPrivOff, end: fPrivOff + fPrivSz})
					if fPrivOff+fPrivSz > maxEnd {
						maxEnd = fPrivOff + fPrivSz
					}
					_, _, _, _, _, _, _, subrRel, _, pOK := parseCFFDictEx(fPrivSlice)
					if !pOK {
						return false
					}
					if subrRel > 0 {
						lsubAbs := fPrivOff + subrRel
						lsubItems, lsubEnd, lsOK := parseCFFIndex(b, lsubAbs)
						if !lsOK || !validateCFFCodeIndexItems(lsubItems) {
							return false
						}
						covered = append(covered, byteSpan{start: lsubAbs, end: lsubEnd})
						if lsubEnd > maxEnd {
							maxEnd = lsubEnd
						}
						fdLocalSubrs[fi] = fdSubrs{items: lsubItems, used: make([]bool, len(lsubItems))}
					}
				}
			}
		}
		var topLocalSubrs fdSubrs
		if privSize > 0 {
			if privOff < 0 || uint64(privOff)+uint64(privSize) > uint64(len(b)) {
				return false
			}
			privSlice := b[privOff : privOff+privSize]
			if hasConcealedHighEntropy(privSlice) {
				return false
			}
			covered = append(covered, byteSpan{start: privOff, end: privOff + privSize})
			if privOff+privSize > maxEnd {
				maxEnd = privOff + privSize
			}
			_, _, _, _, _, _, _, subrRel, _, pOK := parseCFFDictEx(privSlice)
			if !pOK {
				return false
			}
			if subrRel > 0 {
				lsubAbs := privOff + subrRel
				lsubItems, lsubEnd, lsOK := parseCFFIndex(b, lsubAbs)
				if !lsOK || !validateCFFCodeIndexItems(lsubItems) {
					return false
				}
				covered = append(covered, byteSpan{start: lsubAbs, end: lsubEnd})
				if lsubEnd > maxEnd {
					maxEnd = lsubEnd
				}
				topLocalSubrs = fdSubrs{items: lsubItems, used: make([]bool, len(lsubItems))}
			}
		}

		// Execute all Type2 CharStrings.
		for gi, cs := range csItems {
			curLSubs := topLocalSubrs
			if len(fdLocalSubrs) > 0 {
				fdIdx := 0
				if gi < len(fdMap) {
					fdIdx = fdMap[gi]
				}
				if fdIdx < 0 || fdIdx >= len(fdLocalSubrs) {
					return false
				}
				curLSubs = fdLocalSubrs[fdIdx]
			}
			ctxExec := t2ExecCtx{
				gsubs:    gsubItems,
				gsubUsed: gsubUsed,
				lsubs:    curLSubs.items,
				lsubUsed: curLSubs.used,
				maxSteps: 200000,
			}
			ended, gOK := ctxExec.exec(cs, 0)
			totalSteps += ctxExec.steps
			if !gOK || !ended || totalSteps > 5000000 {
				return false
			}
		}
		for i, ls := range topLocalSubrs.items {
			if !topLocalSubrs.used[i] {
				if !validateUncalledSubr(ls, false) {
					return false
				}
				if len(ls) < minEntropyBytes {
					aggUncalledSubrs = append(aggUncalledSubrs, ls...)
				}
			}
		}
		for _, fls := range fdLocalSubrs {
			for i, ls := range fls.items {
				if !fls.used[i] {
					if !validateUncalledSubr(ls, false) {
						return false
					}
					if len(ls) < minEntropyBytes {
						aggUncalledSubrs = append(aggUncalledSubrs, ls...)
					}
				}
			}
		}
	}
	for i, gs := range gsubItems {
		if !gsubUsed[i] {
			if !validateUncalledSubr(gs, false) {
				return false
			}
			if len(gs) < minEntropyBytes {
				aggUncalledSubrs = append(aggUncalledSubrs, gs...)
			}
		}
	}
	if len(aggUncalledSubrs) >= minEntropyBytes && hasConcealedHighEntropyThresh(aggUncalledSubrs, 7.80) {
		return false
	}
	if !checkGapsEntropy(b, covered, 0, maxEnd) {
		return false
	}
	return len(b)-maxEnd <= 64
}

func parseCFF2Index(b []byte, pos int) (items [][]byte, nextPos int, ok bool) {
	if pos < 0 || pos+4 > len(b) {
		return nil, 0, false
	}
	count := int(binary.BigEndian.Uint32(b[pos : pos+4]))
	if count == 0 {
		return nil, pos + 4, true
	}
	if count > 131072 || pos+5 > len(b) {
		return nil, 0, false
	}
	offSize := int(b[pos+4])
	if offSize < 1 || offSize > 4 {
		return nil, 0, false
	}
	offTableStart := pos + 5
	offTableBytes := (count + 1) * offSize
	if offTableStart+offTableBytes > len(b) {
		return nil, 0, false
	}
	readOff := func(idx int) int {
		p := offTableStart + idx*offSize
		v := 0
		for k := 0; k < offSize; k++ {
			v = (v << 8) | int(b[p+k])
		}
		return v
	}
	dataBase := offTableStart + offTableBytes - 1
	prevOff := readOff(0)
	if prevOff != 1 {
		return nil, 0, false
	}
	items = make([][]byte, 0, count)
	for i := 1; i <= count; i++ {
		curOff := readOff(i)
		if curOff < prevOff || dataBase+curOff > len(b) {
			return nil, 0, false
		}
		items = append(items, b[dataBase+prevOff:dataBase+curOff])
		prevOff = curOff
	}
	return items, dataBase + prevOff, true
}

func isValidCFF2Font(b []byte) bool {
	if len(b) < 5 || b[0] != 2 || b[1] != 0 {
		return false
	}
	hdrSize := int(b[2])
	tdLen := int(binary.BigEndian.Uint16(b[3:5]))
	if hdrSize < 5 || hdrSize+tdLen > len(b) {
		return false
	}
	topDict := b[hdrSize : hdrSize+tdLen]
	if _, highEnt := checkHighEntropy(topDict); highEnt {
		return false
	}
	csOff, _, _, _, _, fdArrOff, fdSelOff, _, vstoreOff, dok := parseCFFDictEx(topDict)
	if !dok || csOff <= 0 || csOff >= len(b) {
		return false
	}
	gsubItems, globalSubrEnd, ok := parseCFF2Index(b, hdrSize+tdLen)
	if !ok || !validateCFFCodeIndexItems(gsubItems) {
		return false
	}
	csItems, csEnd, ok := parseCFF2Index(b, csOff)
	if !ok || len(csItems) == 0 || !validateCFFCodeIndexItems(csItems) {
		return false
	}
	covered := []byteSpan{
		{start: 0, end: globalSubrEnd},
		{start: csOff, end: csEnd},
	}
	maxEnd := max(globalSubrEnd, csEnd)
	var regionCounts []int
	if vstoreOff > 0 {
		if vstoreOff+4 > len(b) {
			return false
		}
		vsLen := int(binary.BigEndian.Uint16(b[vstoreOff : vstoreOff+2]))
		vsEnd := vstoreOff + 2 + vsLen
		if vsLen < 8 || vsEnd > len(b) {
			return false
		}
		vs := b[vstoreOff+2 : vsEnd]
		if binary.BigEndian.Uint16(vs[0:2]) != 1 {
			return false
		}
		regListOff := int(binary.BigEndian.Uint32(vs[2:6]))
		ivdCnt := int(binary.BigEndian.Uint16(vs[6:8]))
		if regListOff >= len(vs) || 8+ivdCnt*4 > len(vs) {
			return false
		}
		regionCounts = make([]int, ivdCnt)
		for k := 0; k < ivdCnt; k++ {
			ivdOff := int(binary.BigEndian.Uint32(vs[8+k*4 : 12+k*4]))
			if ivdOff+6 > len(vs) {
				return false
			}
			regionCounts[k] = int(binary.BigEndian.Uint16(vs[ivdOff+4 : ivdOff+6]))
		}
		if hasConcealedHighEntropy(b[vstoreOff:vsEnd]) {
			return false
		}
		covered = append(covered, byteSpan{start: vstoreOff, end: vsEnd})
		if vsEnd > maxEnd {
			maxEnd = vsEnd
		}
	}
	numGlyphs := len(csItems)
	var fdMap []int
	if fdSelOff > 0 {
		var fdSelEnd int
		var fsOK bool
		fdMap, fdSelEnd, fsOK = parseCFFFDSelect(b, fdSelOff, numGlyphs)
		if !fsOK {
			return false
		}
		covered = append(covered, byteSpan{start: fdSelOff, end: fdSelEnd})
		if fdSelEnd > maxEnd {
			maxEnd = fdSelEnd
		}
	}
	type fdSubrs struct {
		items [][]byte
		used  []bool
	}
	var fdLocalSubrs []fdSubrs
	if fdArrOff > 0 {
		fdItems, fdArrEnd, fok := parseCFF2Index(b, fdArrOff)
		if !fok || len(fdItems) == 0 {
			return false
		}
		if _, highEnt := checkHighEntropy(b[fdArrOff:fdArrEnd]); highEnt {
			return false
		}
		covered = append(covered, byteSpan{start: fdArrOff, end: fdArrEnd})
		if fdArrEnd > maxEnd {
			maxEnd = fdArrEnd
		}
		fdLocalSubrs = make([]fdSubrs, len(fdItems))
		for fi, fdDict := range fdItems {
			_, _, _, fPrivSz, fPrivOff, _, _, _, _, fOK := parseCFFDictEx(fdDict)
			if !fOK {
				return false
			}
			if fPrivSz > 0 {
				if fPrivOff < 0 || uint64(fPrivOff)+uint64(fPrivSz) > uint64(len(b)) {
					return false
				}
				fPrivSlice := b[fPrivOff : fPrivOff+fPrivSz]
				if hasConcealedHighEntropy(fPrivSlice) {
					return false
				}
				covered = append(covered, byteSpan{start: fPrivOff, end: fPrivOff + fPrivSz})
				if fPrivOff+fPrivSz > maxEnd {
					maxEnd = fPrivOff + fPrivSz
				}
				_, _, _, _, _, _, _, subrRel, _, pOK := parseCFFDictEx(fPrivSlice)
				if !pOK {
					return false
				}
				if subrRel > 0 {
					lsubAbs := fPrivOff + subrRel
					lsubItems, lsubEnd, lsOK := parseCFF2Index(b, lsubAbs)
					if !lsOK || !validateCFFCodeIndexItems(lsubItems) {
						return false
					}
					covered = append(covered, byteSpan{start: lsubAbs, end: lsubEnd})
					if lsubEnd > maxEnd {
						maxEnd = lsubEnd
					}
					fdLocalSubrs[fi] = fdSubrs{items: lsubItems, used: make([]bool, len(lsubItems))}
				}
			}
		}
	}
	gsubUsed := make([]bool, len(gsubItems))
	totalSteps := 0
	for gi, cs := range csItems {
		var curLSubs fdSubrs
		if len(fdLocalSubrs) > 0 {
			fdIdx := 0
			if gi < len(fdMap) {
				fdIdx = fdMap[gi]
			}
			if fdIdx < 0 || fdIdx >= len(fdLocalSubrs) {
				return false
			}
			curLSubs = fdLocalSubrs[fdIdx]
		}
		ctxExec := t2ExecCtx{
			gsubs:        gsubItems,
			gsubUsed:     gsubUsed,
			lsubs:        curLSubs.items,
			lsubUsed:     curLSubs.used,
			isCFF2:       true,
			regionCounts: regionCounts,
			maxSteps:     200000,
		}
		ended, gOK := ctxExec.exec(cs, 0)
		totalSteps += ctxExec.steps
		if !gOK || !ended || totalSteps > 5000000 {
			return false
		}
	}
	var aggUncalledSubrs []byte
	for i, gs := range gsubItems {
		if !gsubUsed[i] {
			if !validateUncalledSubr(gs, true) {
				return false
			}
			if len(gs) < minEntropyBytes {
				aggUncalledSubrs = append(aggUncalledSubrs, gs...)
			}
		}
	}
	for _, fls := range fdLocalSubrs {
		for i, ls := range fls.items {
			if !fls.used[i] {
				if !validateUncalledSubr(ls, true) {
					return false
				}
				if len(ls) < minEntropyBytes {
					aggUncalledSubrs = append(aggUncalledSubrs, ls...)
				}
			}
		}
	}
	if len(aggUncalledSubrs) >= minEntropyBytes && hasConcealedHighEntropyThresh(aggUncalledSubrs, 7.80) {
		return false
	}
	if !checkGapsEntropy(b, covered, 0, maxEnd) {
		return false
	}
	return len(b)-maxEnd <= 64
}

func parseDERHeader(buf []byte, off int) (tag byte, contentStart, contentEnd int, ok bool) {
	if off < 0 || off+2 > len(buf) {
		return 0, 0, 0, false
	}
	tag = buf[off]
	off++
	lenByte := buf[off]
	off++
	var contentLen int
	if lenByte < 0x80 {
		contentLen = int(lenByte)
	} else {
		numLenBytes := int(lenByte & 0x7f)
		if numLenBytes == 0 || numLenBytes > 4 || off+numLenBytes > len(buf) || buf[off] == 0 {
			return 0, 0, 0, false
		}
		for i := 0; i < numLenBytes; i++ {
			contentLen = (contentLen << 8) | int(buf[off+i])
		}
		if numLenBytes == 1 && contentLen < 0x80 {
			return 0, 0, 0, false
		}
		off += numLenBytes
	}
	if contentLen < 0 || off+contentLen > len(buf) {
		return 0, 0, 0, false
	}
	return tag, off, off + contentLen, true
}

func validateDERSubtree(buf []byte, start, end, depth, maxPrimBytes int, aggPrim *[]byte) bool {
	if depth > 16 || start < 0 || end > len(buf) || start > end {
		return false
	}
	p := start
	for p < end {
		tag, s, e, ok := parseDERHeader(buf, p)
		if !ok || e > end {
			return false
		}
		if (tag & 0x20) != 0 {
			if !validateDERSubtree(buf, s, e, depth+1, maxPrimBytes, aggPrim) {
				return false
			}
		} else {
			if maxPrimBytes >= 0 && e-s > maxPrimBytes && hasConcealedHighEntropy(buf[s:e]) {
				return false
			}
			if aggPrim != nil {
				*aggPrim = append(*aggPrim, buf[s:e]...)
			}
		}
		p = e
	}
	return p == end
}

func isValidPKCS7SignedDataDER(der []byte) bool {
	tOuter, sOuter, eOuter, ok := parseDERHeader(der, 0)
	if !ok || tOuter != 0x30 || eOuter != len(der) {
		return false
	}
	tOID, sOID, eOID, ok := parseDERHeader(der, sOuter)
	pkcs7SignedDataOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	if !ok || tOID != 0x06 || !bytes.Equal(der[sOID:eOID], pkcs7SignedDataOID) {
		return false
	}
	tCtx, sCtx, eCtx, ok := parseDERHeader(der, eOID)
	if !ok || tCtx != 0xa0 || eCtx != eOuter {
		return false
	}
	tSD, sSD, eSD, ok := parseDERHeader(der, sCtx)
	if !ok || tSD != 0x30 || eSD != eCtx {
		return false
	}
	tVer, sVer, eVer, ok := parseDERHeader(der, sSD)
	if !ok || tVer != 0x02 || eVer-sVer < 1 || eVer-sVer > 4 {
		return false
	}
	// digestAlgorithms SET OF (0x31)
	tDig, sDig, eDig, ok := parseDERHeader(der, eVer)
	if !ok || tDig != 0x31 || eDig > eSD {
		return false
	}
	var digPrims []byte
	if !validateDERSubtree(der, sDig, eDig, 1, 255, &digPrims) {
		return false
	}
	if len(digPrims) >= minEntropyBytes && hasConcealedHighEntropyThresh(digPrims, 6.80) {
		return false
	}
	// encapContentInfo SEQUENCE (0x30)
	tECI, sECI, eECI, ok := parseDERHeader(der, eDig)
	if !ok || tECI != 0x30 || eECI > eSD {
		return false
	}
	var eciPrims []byte
	if !validateDERSubtree(der, sECI, eECI, 1, 255, &eciPrims) {
		return false
	}
	if len(eciPrims) >= minEntropyBytes && hasConcealedHighEntropyThresh(eciPrims, 6.80) {
		return false
	}
	pos := eECI
	// Optional [0] certificates (0xa0)
	if pos < eSD && der[pos] == 0xa0 {
		tCerts, sCerts, eCerts, cOK := parseDERHeader(der, pos)
		if !cOK || tCerts != 0xa0 || eCerts > eSD {
			return false
		}
		var certPrims []byte
		if !validateDERSubtree(der, sCerts, eCerts, 1, 550, &certPrims) {
			return false
		}
		if len(certPrims) >= minEntropyBytes && checkMaxEntWindowIncompressible(certPrims, 7.20) {
			return false
		}
		if certs, cErr := x509.ParseCertificates(der[sCerts:eCerts]); cErr != nil || len(certs) == 0 {
			return false
		}
		pos = eCerts
	}
	// Optional [1] crls (0xa1)
	if pos < eSD && der[pos] == 0xa1 {
		tCRLs, sCRLs, eCRLs, cOK := parseDERHeader(der, pos)
		if !cOK || tCRLs != 0xa1 || eCRLs > eSD {
			return false
		}
		var crlPrims []byte
		if !validateDERSubtree(der, sCRLs, eCRLs, 1, 512, &crlPrims) {
			return false
		}
		if len(crlPrims) >= minEntropyBytes && hasConcealedHighEntropyThresh(crlPrims, 6.80) {
			return false
		}
		pos = eCRLs
	}
	// signerInfos SET OF (0x31)
	tSI, sSI, eSI, ok := parseDERHeader(der, pos)
	if !ok || tSI != 0x31 || eSI != eSD {
		return false
	}
	var siPrims []byte
	if !validateDERSubtree(der, sSI, eSI, 1, 512, &siPrims) {
		return false
	}
	if len(siPrims) >= minEntropyBytes {
		if hasConcealedHighEntropyThresh(siPrims, 7.65) {
			return false
		}
		if dom, ok := stripDominantByteIfOver(siPrims, 10); ok && len(dom) >= minEntropyBytes {
			if hasConcealedHighEntropyThresh(dom, 6.80) || hasBitAgnosticIncompressible(dom, 5.80, 0.85) {
				return false
			}
		}
	}
	if len(siPrims) > 1536 && (hasConcealedHighEntropyThresh(siPrims, 6.80) || hasBitAgnosticIncompressible(siPrims, 5.80, 0.85)) {
		return false
	}
	return true
}

func isValidSFNTDSIG(b []byte) bool {
	if len(b) < 8 || binary.BigEndian.Uint32(b[0:4]) != 0x00000001 {
		return false
	}
	numSigs := int(binary.BigEndian.Uint16(b[4:6]))
	flags := binary.BigEndian.Uint16(b[6:8])
	if numSigs == 0 {
		return flags == 0 && len(b) == 8
	}
	if numSigs < 1 || numSigs > 16 || flags > 1 || 8+numSigs*12 > len(b) {
		return false
	}
	spans := make([]byteSpan, 0, numSigs+1)
	spans = append(spans, byteSpan{start: 0, end: 8 + numSigs*12})
	maxEnd := 8 + numSigs*12
	var smallAgg []byte
	for i := 0; i < numSigs; i++ {
		rec := b[8+i*12 : 20+i*12]
		format := binary.BigEndian.Uint32(rec[0:4])
		sigLen := binary.BigEndian.Uint32(rec[4:8])
		sigOff := binary.BigEndian.Uint32(rec[8:12])
		if format != 1 || sigLen <= 8 || sigOff < uint32(8+numSigs*12) || uint64(sigOff)+uint64(sigLen) > uint64(len(b)) {
			return false
		}
		blk := b[sigOff : sigOff+sigLen]
		res1 := binary.BigEndian.Uint16(blk[0:2])
		res2 := binary.BigEndian.Uint16(blk[2:4])
		cbSig := binary.BigEndian.Uint32(blk[4:8])
		if res1 != 0 || res2 != 0 || cbSig < 4 || 8+uint64(cbSig) > uint64(sigLen) || uint64(sigLen)-(8+uint64(cbSig)) > 4 {
			return false
		}
		if int(sigOff+sigLen) > maxEnd {
			maxEnd = int(sigOff + sigLen)
		}
		spans = append(spans, byteSpan{start: int(sigOff), end: int(sigOff + sigLen)})
		if cbSig < minEntropyBytes {
			smallAgg = append(smallAgg, blk[8:8+cbSig]...)
		} else if !isValidPKCS7SignedDataDER(blk[8 : 8+cbSig]) {
			return false
		}
	}
	if len(b)-maxEnd > 4 {
		return false
	}
	if !checkGapsEntropy(b, spans, 0, maxEnd) {
		return false
	}
	if len(smallAgg) >= minEntropyBytes && hasConcealedHighEntropy(smallAgg) {
		return false
	}
	return true
}

func parseGvarPackedPoints(buf []byte) (numPts int, adv int, ok bool) {
	if len(buf) < 1 {
		return 0, 0, false
	}
	cnt := int(buf[0])
	pos := 1
	if cnt == 0 {
		return 0, 1, true
	}
	if cnt&0x80 != 0 {
		if pos >= len(buf) {
			return 0, 0, false
		}
		cnt = ((cnt & 0x7f) << 8) | int(buf[pos])
		pos++
	}
	if cnt == 0 {
		return 0, pos, true
	}
	read := 0
	for read < cnt {
		if pos >= len(buf) {
			return 0, 0, false
		}
		ctrl := buf[pos]
		pos++
		runLen := int(ctrl&0x7f) + 1
		elemSz := 1
		if ctrl&0x80 != 0 {
			elemSz = 2
		}
		need := runLen * elemSz
		if pos+need > len(buf) {
			return 0, 0, false
		}
		pos += need
		read += runLen
	}
	if read != cnt {
		return 0, 0, false
	}
	return cnt, pos, true
}

func parseGvarPackedDeltas(buf []byte, numPts int) (adv int, ok bool) {
	pos := 0
	read := 0
	for read < numPts {
		if pos >= len(buf) {
			return 0, false
		}
		ctrl := buf[pos]
		pos++
		runLen := int(ctrl&0x3f) + 1
		if ctrl&0x80 != 0 {
			// DELTAS_ARE_ZERO: 0 bytes
		} else if ctrl&0x40 != 0 {
			if pos+2*runLen > len(buf) {
				return 0, false
			}
			pos += 2 * runLen
		} else {
			if pos+runLen > len(buf) {
				return 0, false
			}
			pos += runLen
		}
		read += runLen
	}
	if read != numPts {
		return 0, false
	}
	return pos, true
}

func isValidSFNTGvar(b []byte, maxpNumGlyphs int, hasMaxp bool, glyphNumPts []int) bool {
	if len(b) < 20 || binary.BigEndian.Uint32(b[0:4]) != 0x00010000 {
		return false
	}
	axisCount := int(binary.BigEndian.Uint16(b[4:6]))
	sharedTupleCount := int(binary.BigEndian.Uint16(b[6:8]))
	offShared := uint64(binary.BigEndian.Uint32(b[8:12]))
	glyphCount := int(binary.BigEndian.Uint16(b[12:14]))
	flags := binary.BigEndian.Uint16(b[14:16])
	offGlyphVar := uint64(binary.BigEndian.Uint32(b[16:20]))
	if axisCount < 1 || axisCount > 64 || flags > 1 || glyphCount < 1 {
		return false
	}
	if hasMaxp && glyphCount != maxpNumGlyphs {
		return false
	}
	elemSz := uint64(2)
	if flags&1 != 0 {
		elemSz = 4
	}
	offTableEnd := uint64(20) + uint64(glyphCount+1)*elemSz
	if offShared < offTableEnd || offShared > uint64(len(b)) {
		return false
	}
	sharedEnd := offShared + uint64(sharedTupleCount)*uint64(axisCount)*2
	if sharedEnd > offGlyphVar || offGlyphVar > uint64(len(b)) || offGlyphVar-sharedEnd > 64 {
		return false
	}
	if sharedEnd > offShared {
		sh := b[offShared:sharedEnd]
		if len(sh) >= minEntropyBytes && (hasConcealedHighEntropyThresh(sh, 5.50) || hasBitAgnosticIncompressible(sh, 5.50, 0.70)) {
			return false
		}
	}
	gvdBase := int(offGlyphVar)
	remLen := uint64(len(b) - gvdBase)
	var prev uint64
	var aggVarData []byte
	for i := 0; i <= glyphCount; i++ {
		p := 20 + i*int(elemSz)
		var curOff uint64
		if elemSz == 2 {
			curOff = uint64(binary.BigEndian.Uint16(b[p:p+2])) * 2
		} else {
			curOff = uint64(binary.BigEndian.Uint32(b[p : p+4]))
		}
		if curOff < prev || curOff > remLen {
			return false
		}
		if i > 0 && curOff > prev {
			gIdx := i - 1
			totalPts := 4
			if gIdx < len(glyphNumPts) {
				totalPts = glyphNumPts[gIdx] + 4
			}
			gvd := b[gvdBase+int(prev) : gvdBase+int(curOff)]
			if len(gvd) < 4 {
				return false
			}
			tvc := binary.BigEndian.Uint16(gvd[0:2])
			tupleCount := int(tvc & 0x0FFF)
			dataOff := int(binary.BigEndian.Uint16(gvd[2:4]))
			if tupleCount < 1 || dataOff < 4+tupleCount*4 || dataOff > len(gvd) {
				return false
			}
			pos := 4
			sumVarData := 0
			type tupleHdr struct {
				varDataSz int
				tupleIdx  uint16
			}
			hdrs := make([]tupleHdr, tupleCount)
			for t := 0; t < tupleCount; t++ {
				if pos+4 > dataOff {
					return false
				}
				varDataSz := int(binary.BigEndian.Uint16(gvd[pos : pos+2]))
				tupleIdx := binary.BigEndian.Uint16(gvd[pos+2 : pos+4])
				pos += 4
				if tupleIdx&0x8000 != 0 {
					pos += axisCount * 2
				}
				if tupleIdx&0x4000 != 0 {
					pos += axisCount * 4
				}
				if pos > dataOff {
					return false
				}
				hdrs[t] = tupleHdr{varDataSz: varDataSz, tupleIdx: tupleIdx}
				sumVarData += varDataSz
			}
			sd := gvd[dataOff:]
			if sumVarData > len(sd) {
				return false
			}
			sdPos := 0
			sharedPts := 0
			hasSharedPts := (tvc & 0x8000) != 0
			if hasSharedPts {
				sp, adv, pOK := parseGvarPackedPoints(sd)
				if !pOK {
					return false
				}
				sharedPts = sp
				sdPos += adv
			}
			for t := 0; t < tupleCount; t++ {
				th := hdrs[t]
				if sdPos+th.varDataSz > len(sd) {
					return false
				}
				tv := sd[sdPos : sdPos+th.varDataSz]
				sdPos += th.varDataSz
				if th.varDataSz == 0 {
					continue
				}
				tp := 0
				nPts := sharedPts
				if th.tupleIdx&0x2000 != 0 {
					pp, adv, pOK := parseGvarPackedPoints(tv)
					if !pOK {
						return false
					}
					nPts = pp
					tp = adv
				} else if !hasSharedPts {
					return false
				}
				if nPts == 0 {
					nPts = totalPts
				}
				advX, okX := parseGvarPackedDeltas(tv[tp:], nPts)
				if !okX {
					return false
				}
				tp += advX
				advY, okY := parseGvarPackedDeltas(tv[tp:], nPts)
				if !okY {
					return false
				}
				if tp+advY != len(tv) {
					return false
				}
			}
			if len(sd)-sdPos > 4 {
				return false
			}
			aggVarData = append(aggVarData, sd...)
		}
		prev = curOff
	}
	if len(aggVarData) >= minEntropyBytes && (hasConcealedHighEntropyThresh(aggVarData, 7.65) || hasLowDistIncompressible(aggVarData, 134, 5.80, 0.85)) {
		return false
	}
	return remLen-prev <= 4
}

func isValidSFNTMeta(b []byte) bool {
	if len(b) < 16 || binary.BigEndian.Uint32(b[0:4]) != 1 || binary.BigEndian.Uint32(b[4:8]) != 0 {
		return false
	}
	dataOffset := int(binary.BigEndian.Uint32(b[8:12]))
	cnt := int(binary.BigEndian.Uint32(b[12:16]))
	if cnt < 0 || cnt > 256 {
		return false
	}
	hdrEnd := 16 + cnt*12
	if hdrEnd > len(b) || dataOffset < hdrEnd || dataOffset > len(b) {
		return false
	}
	spans := make([]byteSpan, 0, cnt+1)
	spans = append(spans, byteSpan{start: 0, end: hdrEnd})
	maxEnd := hdrEnd
	var applSmall, otherSmall []byte
	for i := 0; i < cnt; i++ {
		rec := b[16+i*12 : 28+i*12]
		for j := 0; j < 4; j++ {
			if rec[j] < 0x20 || rec[j] > 0x7e {
				return false
			}
		}
		tag := string(rec[0:4])
		recOff := int(binary.BigEndian.Uint32(rec[4:8]))
		recLen := int(binary.BigEndian.Uint32(rec[8:12]))
		if recOff < dataOffset || recLen < 0 || uint64(recOff)+uint64(recLen) > uint64(len(b)) {
			return false
		}
		spans = append(spans, byteSpan{start: recOff, end: recOff + recLen})
		if recOff+recLen > maxEnd {
			maxEnd = recOff + recLen
		}
		recData := b[recOff : recOff+recLen]
		if tag == "appl" {
			if recLen >= 24 {
				if binary.BigEndian.Uint32(recData[0:4]) != 2 ||
					binary.BigEndian.Uint32(recData[4:8]) != 0 ||
					binary.LittleEndian.Uint32(recData[8:12]) != 0x18 {
					return false
				}
				if recLen >= 512 {
					pay := recData[24:]
					c7 := 0
					for _, x := range pay {
						if x < 0x80 {
							c7++
						}
					}
					d := distinctBytesCount(pay)
					entPay, _ := shannonEntropyAndPrintable(pay)
					zrPay := zlibCompressedRatio(pay)
					if c7*100 >= len(pay)*99 || c7*100 <= len(pay) {
						if entPay >= 6.85 || (len(pay) >= 768 && entPay >= 6.40 && zrPay >= 0.92) {
							return false
						}
					}
					if d <= 64 && entPay >= 5.80 && zrPay >= 0.92 {
						return false
					}
					if len(pay) >= 768 && d <= 132 && entPay >= 5.80 && zrPay >= 0.88 {
						return false
					}
					if len(pay) >= 3072 && (d <= 160 || ((c7*100 <= len(pay) || c7*100 >= len(pay)*90) && zrPay >= 0.90)) && entPay >= 6.40 && zrPay >= 0.88 {
						return false
					}
					if len(pay) >= 4096 && hasLowDistIncompressible(pay, 136, 6.40, 0.88) {
						return false
					}
				}
			}
			if recLen >= minEntropyBytes {
				if hasConcealedHighEntropyThresh(recData, 7.60) {
					return false
				}
				if dom, ok := stripDominantByteIfOver(recData, 12); ok && len(dom) >= minEntropyBytes && checkMaxEntWindowIncompressible(dom, 7.60) {
					return false
				}
			} else {
				applSmall = append(applSmall, recData...)
			}
		} else {
			if recLen >= minEntropyBytes {
				if hasConcealedHighEntropy(recData) {
					return false
				}
			} else {
				otherSmall = append(otherSmall, recData...)
			}
		}
	}
	if len(b)-maxEnd > 4 {
		return false
	}
	if !checkGapsEntropy(b, spans, 0, maxEnd) {
		return false
	}
	if len(applSmall) >= minEntropyBytes {
		if hasConcealedHighEntropyThresh(applSmall, 7.60) {
			return false
		}
		if dom, ok := stripDominantByteIfOver(applSmall, 12); ok && len(dom) >= minEntropyBytes && checkMaxEntWindowIncompressible(dom, 7.60) {
			return false
		}
	}
	if len(otherSmall) >= minEntropyBytes && hasConcealedHighEntropy(otherSmall) {
		return false
	}
	return true
}

func hasSFNTCalibratedTableHighEntropy(b []byte) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	if _, highEnt := checkHighEntropyThresh(b, 7.65); highEnt {
		return true
	}
	if collapsed := collapseRepeatedBytes(b, 16); len(collapsed) >= minEntropyBytes && len(collapsed) < len(b)*9/10 {
		if _, highEnt := checkHighEntropyThresh(collapsed, 7.65); highEnt {
			return true
		}
	}
	if pCollapsed := collapseRepeatedPeriodic(b, 32, 4); len(pCollapsed) >= minEntropyBytes && len(pCollapsed) < len(b)*9/10 {
		if _, highEnt := checkHighEntropyThresh(pCollapsed, 7.65); highEnt {
			return true
		}
	}
	if hasConstantLanePlusHighEntResidualThresh(b, 7.65) {
		return true
	}
	if stripped := stripControlBytesForInspection(b); len(stripped) >= minEntropyBytes && len(stripped) < len(b)*9/10 {
		if _, highEnt := checkHighEntropyThresh(stripped, 7.80); highEnt {
			return true
		}
	}
	if dom, ok := stripDominantByteIfOver(b, 20); ok && len(dom) >= minEntropyBytes {
		if checkMaxEntWindowIncompressible(dom, 7.80) {
			return true
		}
	}
	if hasLowDistIncompressible(b, 134, 5.80, 0.85) {
		return true
	}
	return false
}

func isValidSFNTEBLC(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	if ver != 0x00020000 && ver != 0x00030000 {
		return false
	}
	numSizes := binary.BigEndian.Uint32(b[4:8])
	if numSizes < 1 || 8+uint64(numSizes)*48 > uint64(len(b)) {
		return false
	}
	minArrOff := uint64(8) + uint64(numSizes)*48
	for i := uint32(0); i < numSizes; i++ {
		off := 8 + int(i)*48
		ioff := uint64(binary.BigEndian.Uint32(b[off : off+4]))
		isz := uint64(binary.BigEndian.Uint32(b[off+4 : off+8]))
		numSub := uint64(binary.BigEndian.Uint32(b[off+8 : off+12]))
		if ioff < minArrOff || ioff+isz > uint64(len(b)) || numSub*8 > isz {
			return false
		}
	}
	return !hasSFNTCalibratedTableHighEntropy(b)
}

func isValidSFNTEBDT(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	if ver != 0x00020000 && ver != 0x00030000 {
		return false
	}
	return !hasSFNTCalibratedTableHighEntropy(b) && !hasBitAgnosticIncompressible(b, 5.75, 0.75)
}

func isValidTTBytecode(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	p := 0
	for p < len(b) {
		op := b[p]
		p++
		switch {
		case op == 0x40: // NPUSHB
			if p >= len(b) {
				return false
			}
			cnt := int(b[p])
			p++
			if p+cnt > len(b) {
				return false
			}
			p += cnt
		case op == 0x41: // NPUSHW
			if p >= len(b) {
				return false
			}
			cnt := int(b[p])
			p++
			if p+2*cnt > len(b) {
				return false
			}
			p += 2 * cnt
		case op >= 0xB0 && op <= 0xB7: // PUSHB[n]
			cnt := int(op-0xB0) + 1
			if p+cnt > len(b) {
				return false
			}
			p += cnt
		case op >= 0xB8 && op <= 0xBF: // PUSHW[n]
			cnt := int(op-0xB8) + 1
			if p+2*cnt > len(b) {
				return false
			}
			p += 2 * cnt
		}
	}
	return p == len(b)
}

func isValidSFNTPost(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	switch ver {
	case 0x00010000, 0x00030000:
		if len(b) != 32 {
			return false
		}
	case 0x00020000:
		if len(b) < 34 {
			return false
		}
		numGlyphs := int(binary.BigEndian.Uint16(b[32:34]))
		pos := 34 + numGlyphs*2
		if pos > len(b) {
			return false
		}
		for pos < len(b) {
			if len(b)-pos <= 4 && b[pos] == 0 {
				allZero := true
				for k := pos; k < len(b); k++ {
					if b[k] != 0 {
						allZero = false
						break
					}
				}
				if allZero {
					pos = len(b)
					break
				}
			}
			pLen := int(b[pos])
			pos++
			if pos+pLen > len(b) {
				return false
			}
			for k := 0; k < pLen; k++ {
				c := b[pos+k]
				if c < 0x20 || c > 0x7e {
					return false
				}
			}
			pos += pLen
		}
		if pos != len(b) {
			return false
		}
	case 0x00025000:
		if len(b) < 34 {
			return false
		}
		numGlyphs := int(binary.BigEndian.Uint16(b[32:34]))
		if len(b) < 34+numGlyphs || len(b)-(34+numGlyphs) > 4 {
			return false
		}
	case 0x00040000:
		if len(b) < 32 || (len(b)-32)%2 != 0 {
			return false
		}
	default:
		return false
	}
	if len(b) >= minEntropyBytes {
		ent, _ := shannonEntropyAndPrintable(b)
		if ent >= 6.30 && zlibCompressedRatio(b) >= 0.85 {
			return false
		}
		if hasLowDistIncompressible(b, 134, 5.80, 0.85) {
			return false
		}
	}
	return true
}

func isValidSFNTCOLR(b []byte) bool {
	if len(b) < 14 {
		return false
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	if ver != 0 && ver != 1 {
		return false
	}
	numBase := int(binary.BigEndian.Uint16(b[2:4]))
	baseOff := int(binary.BigEndian.Uint32(b[4:8]))
	layerOff := int(binary.BigEndian.Uint32(b[8:12]))
	numLayers := int(binary.BigEndian.Uint16(b[12:14]))
	if numBase > 0 && (baseOff < 14 || uint64(baseOff)+uint64(numBase)*6 > uint64(len(b))) {
		return false
	}
	if numLayers > 0 && (layerOff < 14 || uint64(layerOff)+uint64(numLayers)*4 > uint64(len(b))) {
		return false
	}
	if ver == 1 {
		if len(b) < 34 {
			return false
		}
		for _, offPos := range []int{14, 18, 22, 26, 30} {
			o := int(binary.BigEndian.Uint32(b[offPos : offPos+4]))
			if o != 0 && (o < 34 || o >= len(b)) {
				return false
			}
		}
		return !hasConcealedHighEntropy(b) && !hasLowDistIncompressible(b, 134, 5.80, 0.85)
	}
	return !hasConcealedHighEntropy(b) && !hasBitAgnosticIncompressible(b, 5.80, 0.85)
}

func isValidSFNTCPAL(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	ver := binary.BigEndian.Uint16(b[0:2])
	if ver != 0 && ver != 1 {
		return false
	}
	numEntries := int(binary.BigEndian.Uint16(b[2:4]))
	numPalettes := int(binary.BigEndian.Uint16(b[4:6]))
	numColors := int(binary.BigEndian.Uint16(b[6:8]))
	colorsOff := int(binary.BigEndian.Uint32(b[8:12]))
	if numEntries < 1 || numPalettes < 1 || colorsOff < 12+numPalettes*2 || uint64(colorsOff)+uint64(numColors)*4 > uint64(len(b)) {
		return false
	}
	if ver == 1 {
		if len(b) < 24+numPalettes*2 {
			return false
		}
		for _, offPos := range []int{12 + numPalettes*2, 16 + numPalettes*2, 20 + numPalettes*2} {
			o := int(binary.BigEndian.Uint32(b[offPos : offPos+4]))
			if o != 0 && (o < 24+numPalettes*2 || o >= len(b)) {
				return false
			}
		}
	}
	return !hasConcealedHighEntropy(b) && !hasBitAgnosticIncompressible(b, 5.80, 0.85)
}

func isValidSFNTSVG(b []byte) bool {
	if len(b) < 10 || binary.BigEndian.Uint16(b[0:2]) != 0 {
		return false
	}
	docListOff := int(binary.BigEndian.Uint32(b[2:6]))
	if docListOff < 10 || docListOff+2 > len(b) {
		return false
	}
	numEntries := int(binary.BigEndian.Uint16(b[docListOff : docListOff+2]))
	if numEntries < 1 || docListOff+2+numEntries*12 > len(b) {
		return false
	}
	for i := 0; i < numEntries; i++ {
		rec := b[docListOff+2+i*12 : docListOff+2+(i+1)*12]
		startG := binary.BigEndian.Uint16(rec[0:2])
		endG := binary.BigEndian.Uint16(rec[2:4])
		docOff := int(binary.BigEndian.Uint32(rec[4:8]))
		docLen := int(binary.BigEndian.Uint32(rec[8:12]))
		if endG < startG || docOff < 2+numEntries*12 || uint64(docListOff)+uint64(docOff)+uint64(docLen) > uint64(len(b)) || docLen == 0 {
			return false
		}
		doc := b[docListOff+docOff : docListOff+docOff+docLen]
		if len(doc) >= 3 && doc[0] == 0x1f && doc[1] == 0x8b && doc[2] == 0x08 {
			gr, err := gzip.NewReader(bytes.NewReader(doc))
			if err != nil {
				return false
			}
			inf, rErr := io.ReadAll(io.LimitReader(gr, defaultArchiveMaxEntryBytes+1))
			_ = gr.Close()
			if rErr != nil || len(inf) > defaultArchiveMaxEntryBytes {
				return false
			}
			doc = inf
		}
		if !bytes.Contains(doc, []byte("<svg")) || hasConcealedHighEntropy(doc) {
			return false
		}
	}
	return true
}

func isValidSFNTCmap(b []byte) bool {
	if len(b) < 4 || binary.BigEndian.Uint16(b[0:2]) != 0 {
		return false
	}
	numTables := int(binary.BigEndian.Uint16(b[2:4]))
	hdrEnd := 4 + numTables*8
	if numTables == 0 || hdrEnd > len(b) {
		return false
	}
	for i := 0; i < numTables; i++ {
		subOff := int(binary.BigEndian.Uint32(b[4+i*8+4 : 4+i*8+8]))
		if subOff < hdrEnd || subOff >= len(b) {
			return false
		}
	}
	return !hasSFNTCalibratedTableHighEntropy(b)
}

func isValidSFNTGSUBGPOS(b []byte) bool {
	if len(b) < 10 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	if ver != 0x00010000 && ver != 0x00010001 {
		return false
	}
	hdrMin := 10
	if ver == 0x00010001 {
		hdrMin = 14
		if len(b) < 14 {
			return false
		}
		featVarOff := int(binary.BigEndian.Uint32(b[10:14]))
		if featVarOff != 0 && (featVarOff < 14 || featVarOff >= len(b)) {
			return false
		}
	}
	scriptOff := int(binary.BigEndian.Uint16(b[4:6]))
	featOff := int(binary.BigEndian.Uint16(b[6:8]))
	lookupOff := int(binary.BigEndian.Uint16(b[8:10]))
	validOff := func(o int) bool { return o == 0 || (o >= hdrMin && o < len(b)) }
	if !validOff(scriptOff) || !validOff(featOff) || !validOff(lookupOff) || (scriptOff == 0 && featOff == 0 && lookupOff == 0) {
		return false
	}
	return !hasSFNTCalibratedTableHighEntropy(b)
}

func isValidSFNTGDEF(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[0:4])
	var hdrMin int
	switch ver {
	case 0x00010000:
		hdrMin = 12
	case 0x00010002:
		hdrMin = 14
	case 0x00010003:
		hdrMin = 18
	default:
		return false
	}
	if len(b) < hdrMin {
		return false
	}
	for pos := 4; pos+2 <= 12; pos += 2 {
		o := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		if o != 0 && (o < hdrMin || o >= len(b)) {
			return false
		}
	}
	if ver == 0x00010002 || ver == 0x00010003 {
		o := int(binary.BigEndian.Uint16(b[12:14]))
		if o != 0 && (o < hdrMin || o >= len(b)) {
			return false
		}
	}
	if ver == 0x00010003 {
		o := int(binary.BigEndian.Uint32(b[14:18]))
		if o != 0 && (o < hdrMin || o >= len(b)) {
			return false
		}
	}
	return !hasSFNTCalibratedTableHighEntropy(b)
}

type sfntGlyfInfo struct {
	outlineGlyphs     int
	glyphNumPts       []int
	aggCoordsLen      int
	uniqueGlyphHashes int
	uniqueGlyphShapes int
}

func fnv64aBytes(chunks ...[]byte) uint64 {
	h := uint64(14695981039346656037)
	for _, ch := range chunks {
		for _, x := range ch {
			h ^= uint64(x)
			h *= 1099511628211
		}
		h ^= 0xff
		h *= 1099511628211
	}
	return h
}

func isValidSFNTGlyfWithLoca(glyf, loca []byte, indexToLocFormat uint16) (sfntGlyfInfo, bool) {
	var offsets []uint64
	if indexToLocFormat == 0 {
		if len(loca)%2 != 0 {
			return sfntGlyfInfo{}, false
		}
		offsets = make([]uint64, len(loca)/2)
		var prev uint64
		for i := 0; i < len(offsets); i++ {
			curOff := uint64(binary.BigEndian.Uint16(loca[i*2:i*2+2])) * 2
			if curOff < prev || curOff > uint64(len(glyf)) {
				return sfntGlyfInfo{}, false
			}
			offsets[i] = curOff
			prev = curOff
		}
	} else {
		if len(loca)%4 != 0 {
			return sfntGlyfInfo{}, false
		}
		offsets = make([]uint64, len(loca)/4)
		var prev uint64
		for i := 0; i < len(offsets); i++ {
			curOff := uint64(binary.BigEndian.Uint32(loca[i*4 : i*4+4]))
			if curOff < prev || curOff > uint64(len(glyf)) {
				return sfntGlyfInfo{}, false
			}
			offsets[i] = curOff
			prev = curOff
		}
	}
	if len(offsets) < 2 || offsets[0] != 0 || uint64(len(glyf))-offsets[len(offsets)-1] > 4 {
		return sfntGlyfInfo{}, false
	}
	outlineGlyphs := 0
	glyphNumPts := make([]int, len(offsets)-1)
	uniqHashes := make(map[uint64]struct{}, min(len(offsets), 512))
	uniqShapes := make(map[uint64]struct{}, min(len(offsets), 512))
	var aggInst []byte
	var aggPad []byte
	var aggFlags []byte
	var aggCoords []byte
	for i := 1; i < len(offsets); i++ {
		if offsets[i] == offsets[i-1] {
			continue
		}
		g := glyf[offsets[i-1]:offsets[i]]
		if len(g) < 10 {
			return sfntGlyfInfo{}, false
		}
		uniqHashes[fnv64aBytes(g)] = struct{}{}
		nc := int(int16(binary.BigEndian.Uint16(g[0:2])))
		xMin := int16(binary.BigEndian.Uint16(g[2:4]))
		yMin := int16(binary.BigEndian.Uint16(g[4:6]))
		xMax := int16(binary.BigEndian.Uint16(g[6:8]))
		yMax := int16(binary.BigEndian.Uint16(g[8:10]))
		if nc < -1 || nc > 1000 {
			return sfntGlyfInfo{}, false
		}
		validBox := (xMin <= xMax && yMin <= yMax) || (xMin == 32767 && yMin == 32767 && xMax == -32767 && yMax == -32767)
		if !validBox {
			return sfntGlyfInfo{}, false
		}
		if nc == 0 {
			if len(g) > 16 {
				return sfntGlyfInfo{}, false
			}
			if len(g) > 10 {
				aggPad = append(aggPad, g[10:]...)
			}
			continue
		}
		outlineGlyphs++
		if nc > 0 {
			if 10+2*nc+2 > len(g) {
				return sfntGlyfInfo{}, false
			}
			prevEP := -1
			for c := 0; c < nc; c++ {
				ep := int(binary.BigEndian.Uint16(g[10+c*2 : 12+c*2]))
				if ep <= prevEP {
					return sfntGlyfInfo{}, false
				}
				prevEP = ep
			}
			numPts := prevEP + 1
			glyphNumPts[i-1] = numPts
			instLen := int(binary.BigEndian.Uint16(g[10+2*nc : 12+2*nc]))
			p := 10 + 2*nc + 2
			if p+instLen > len(g) {
				return sfntGlyfInfo{}, false
			}
			if instLen > 0 {
				inst := g[p : p+instLen]
				if instLen >= minEntropyBytes && hasConcealedHighEntropyThresh(inst, 7.65) {
					return sfntGlyfInfo{}, false
				}
				aggInst = append(aggInst, inst...)
			}
			p += instLen
			flagsStart := p
			xBytes, yBytes := 0, 0
			pt := 0
			for pt < numPts && p < len(g) {
				fl := g[p]
				p++
				rep := 1
				if fl&0x08 != 0 {
					if p >= len(g) {
						return sfntGlyfInfo{}, false
					}
					rep += int(g[p])
					p++
				}
				if fl&0x02 != 0 {
					xBytes += rep
				} else if fl&0x10 == 0 {
					xBytes += 2 * rep
				}
				if fl&0x04 != 0 {
					yBytes += rep
				} else if fl&0x20 == 0 {
					yBytes += 2 * rep
				}
				pt += rep
			}
			if pt != numPts || p+xBytes+yBytes > len(g) {
				return sfntGlyfInfo{}, false
			}
			flSlice := g[flagsStart:p]
			if len(flSlice) >= minEntropyBytes && (hasConcealedHighEntropyThresh(flSlice, 5.50) || hasBitAgnosticIncompressible(flSlice, 5.50, 0.85)) {
				return sfntGlyfInfo{}, false
			}
			aggFlags = append(aggFlags, flSlice...)
			coords := g[p : p+xBytes+yBytes]
			if len(coords) >= minEntropyBytes && hasConcealedHighEntropyThresh(coords, 7.50) {
				return sfntGlyfInfo{}, false
			}
			aggCoords = append(aggCoords, coords...)
			uniqShapes[fnv64aBytes(g[0:2], g[10:10+2*nc], flSlice, coords)] = struct{}{}
			rem := len(g) - (p + xBytes + yBytes)
			if rem > 8 {
				return sfntGlyfInfo{}, false
			}
			if rem > 0 {
				aggPad = append(aggPad, g[p+xBytes+yBytes:]...)
			}
		} else if nc == -1 {
			p := 10
			hasInst := false
			compCount := 0
			for {
				if p+4 > len(g) {
					return sfntGlyfInfo{}, false
				}
				compCount++
				fl := binary.BigEndian.Uint16(g[p : p+2])
				p += 4
				if fl&0x0001 != 0 {
					p += 4
				} else {
					p += 2
				}
				if fl&0x0008 != 0 {
					p += 2
				} else if fl&0x0040 != 0 {
					p += 4
				} else if fl&0x0080 != 0 {
					p += 8
				}
				if p > len(g) {
					return sfntGlyfInfo{}, false
				}
				if fl&0x0100 != 0 {
					hasInst = true
				}
				if fl&0x0020 == 0 {
					break
				}
			}
			glyphNumPts[i-1] = compCount
			uniqShapes[fnv64aBytes(g)] = struct{}{}
			if hasInst {
				if p+2 > len(g) {
					return sfntGlyfInfo{}, false
				}
				il := int(binary.BigEndian.Uint16(g[p : p+2]))
				p += 2
				if p+il > len(g) {
					return sfntGlyfInfo{}, false
				}
				if il > 0 {
					inst := g[p : p+il]
					if il >= minEntropyBytes && hasConcealedHighEntropyThresh(inst, 7.65) {
						return sfntGlyfInfo{}, false
					}
					aggInst = append(aggInst, inst...)
				}
				p += il
			}
			rem := len(g) - p
			if rem > 8 {
				return sfntGlyfInfo{}, false
			}
			if rem > 0 {
				aggPad = append(aggPad, g[p:]...)
			}
		}
	}
	if len(aggFlags) >= minEntropyBytes && (hasConcealedHighEntropyThresh(aggFlags, 5.50) || hasBitAgnosticIncompressible(aggFlags, 5.50, 0.75)) {
		return sfntGlyfInfo{}, false
	}
	if len(aggInst) >= minEntropyBytes && hasConcealedHighEntropyThresh(aggInst, 7.65) {
		return sfntGlyfInfo{}, false
	}
	if len(aggPad) >= minEntropyBytes && hasConcealedHighEntropyThresh(aggPad, 6.00) {
		return sfntGlyfInfo{}, false
	}
	if len(aggCoords) >= minEntropyBytes {
		if hasConcealedHighEntropyThresh(aggCoords, 7.75) {
			return sfntGlyfInfo{}, false
		}
		entWhole, _ := shannonEntropyAndPrintable(aggCoords)
		if distinctBytesCount(aggCoords) <= 160 && entWhole >= 5.80 && zlibCompressedRatio(aggCoords) >= 0.85 {
			return sfntGlyfInfo{}, false
		}
		if hasLowDistIncompressible(aggCoords, 64, 5.75, 0.85) || hasLowDistIncompressible(aggCoords, 136, 6.40, 0.88) {
			return sfntGlyfInfo{}, false
		}
		if dom, ok := stripDominantByteIfOver(aggCoords, 20); ok && len(dom) >= minEntropyBytes {
			if hasLowDistIncompressible(dom, 64, 5.75, 0.85) || hasLowDistIncompressible(dom, 136, 6.40, 0.88) {
				return sfntGlyfInfo{}, false
			}
		}
	}
	return sfntGlyfInfo{
		outlineGlyphs:     outlineGlyphs,
		glyphNumPts:       glyphNumPts,
		aggCoordsLen:      len(aggCoords),
		uniqueGlyphHashes: len(uniqHashes),
		uniqueGlyphShapes: len(uniqShapes),
	}, true
}

func isValidSFNTFontAt(data []byte, sfntOff int, dirSpans []byteSpan) ([]byteSpan, uint64, bool) {
	if sfntOff < 0 || sfntOff+12 > len(data) {
		return nil, 0, false
	}
	tag := binary.BigEndian.Uint32(data[sfntOff : sfntOff+4])
	switch tag {
	case 0x00010000, 0x4F54544F /* OTTO */, 0x74727565 /* true */, 0x74797031 /* typ1 */ :
	default:
		return nil, 0, false
	}
	numTables := int(binary.BigEndian.Uint16(data[sfntOff+4 : sfntOff+6]))
	if numTables < 4 || numTables > 128 {
		return nil, 0, false
	}
	dirEnd := sfntOff + 12 + numTables*16
	if dirEnd > len(data) {
		return nil, 0, false
	}
	minTableOff := uint64(dirEnd)
	if sfntOff > 0 {
		minTableOff = 12
	}

	var (
		maxEnd               = uint64(dirEnd)
		hasHead              bool
		headOff, headLen     uint64
		hasMaxp              bool
		maxpOff, maxpLen     uint64
		hasCFF               bool
		cffOff, cffLen       uint64
		hasCFF2              bool
		cff2Off, cff2Len     uint64
		hasLoca              bool
		locaOff, locaLen     uint64
		hasGlyf              bool
		glyfOff, glyfLen     uint64
		hasGvar              bool
		gvarOff, gvarLen     uint64
		hasCvt               bool
		cvtOff, cvtLen       uint64
		hasFpgm              bool
		fpgmOff, fpgmLen     uint64
		hasOutlinesOrMetrics bool
		aggSmall             []byte
	)
	seenTags := make(map[string]struct{}, numTables)
	spans := make([]byteSpan, 0, numTables+1)
	spans = append(spans, byteSpan{start: sfntOff, end: dirEnd})
	for i := 0; i < numTables; i++ {
		rec := data[sfntOff+12+i*16 : sfntOff+12+(i+1)*16]
		for j := 0; j < 4; j++ {
			if rec[j] < 0x20 || rec[j] > 0x7e {
				return nil, 0, false
			}
		}
		tblTag := string(rec[0:4])
		if _, dup := seenTags[tblTag]; dup {
			return nil, 0, false
		}
		seenTags[tblTag] = struct{}{}
		storedCsum := binary.BigEndian.Uint32(rec[4:8])
		tblOff := uint64(binary.BigEndian.Uint32(rec[8:12]))
		tblLen := uint64(binary.BigEndian.Uint32(rec[12:16]))
		if tblOff < minTableOff || tblOff+tblLen > uint64(len(data)) {
			return nil, 0, false
		}
		if tblLen > 0 {
			if tblOff < uint64(dirEnd) && tblOff+tblLen > uint64(sfntOff) {
				return nil, 0, false
			}
			for _, ds := range dirSpans {
				if int(tblOff) < ds.end && int(tblOff+tblLen) > ds.start {
					return nil, 0, false
				}
			}
		}
		if tblOff+tblLen > maxEnd {
			maxEnd = tblOff + tblLen
		}
		spans = append(spans, byteSpan{start: int(tblOff), end: int(tblOff + tblLen)})
		tblBytes := data[tblOff : tblOff+tblLen]
		if tblTag != "head" {
			if sfntChecksum(tblBytes) != storedCsum {
				return nil, 0, false
			}
		}
		if tblLen < minEntropyBytes && tblTag != "loca" {
			aggSmall = append(aggSmall, tblBytes...)
		}
		switch tblTag {
		case "loca", "glyf", "gvar", "CFF ", "CFF2":
			// Validated below with cross-table metadata / structural parsers.
		case "cvt ":
			if tblLen%2 != 0 {
				return nil, 0, false
			}
		case "DSIG":
			if !isValidSFNTDSIG(tblBytes) {
				return nil, 0, false
			}
		case "meta":
			if !isValidSFNTMeta(tblBytes) {
				return nil, 0, false
			}
		case "EBLC", "CBLC", "bloc":
			if !isValidSFNTEBLC(tblBytes) {
				return nil, 0, false
			}
		case "EBDT", "CBDT", "bdat":
			if !isValidSFNTEBDT(tblBytes) {
				return nil, 0, false
			}
		case "cmap":
			if !isValidSFNTCmap(tblBytes) {
				return nil, 0, false
			}
		case "GSUB", "GPOS":
			if !isValidSFNTGSUBGPOS(tblBytes) {
				return nil, 0, false
			}
		case "GDEF":
			if !isValidSFNTGDEF(tblBytes) {
				return nil, 0, false
			}
		case "post":
			if !isValidSFNTPost(tblBytes) {
				return nil, 0, false
			}
		case "COLR":
			if !isValidSFNTCOLR(tblBytes) {
				return nil, 0, false
			}
		case "CPAL":
			if !isValidSFNTCPAL(tblBytes) {
				return nil, 0, false
			}
		case "SVG ":
			if !isValidSFNTSVG(tblBytes) {
				return nil, 0, false
			}
		case "kern":
			if tblLen >= minEntropyBytes && (hasConcealedHighEntropy(tblBytes) || hasBitAgnosticIncompressible(tblBytes, 5.75, 0.80)) {
				return nil, 0, false
			}
		case "fpgm":
			if !isValidTTBytecode(tblBytes) {
				return nil, 0, false
			}
			if tblLen >= minEntropyBytes && (hasConcealedHighEntropy(tblBytes) || hasBitAgnosticIncompressible(tblBytes, 5.75, 0.80)) {
				return nil, 0, false
			}
		case "prep":
			if !isValidTTBytecode(tblBytes) {
				return nil, 0, false
			}
			if tblLen >= minEntropyBytes {
				if hasConcealedHighEntropy(tblBytes) || hasBitAgnosticIncompressible(tblBytes, 6.70, 0.88) || (tblLen >= 512 && hasLowDistIncompressible(tblBytes, 64, 5.80, 0.85)) {
					return nil, 0, false
				}
			}
		default:
			if tblLen >= minEntropyBytes {
				switch tblTag {
				case "Zapf", "morx", "mort", "HVAR", "VVAR", "MVAR", "AVAR", "prop", "hmtx", "vmtx",
					"fond", "MATH", "sbix", "feat", "just", "lcar", "opbd", "ankr",
					"bsln", "trak", "fdsc", "fmtx", "vhea", "xref", "acnt", "bhed", "hdmx", "LTSH", "OS/2",
					"VDMX", "PCLT", "gasp", "BASE", "JSTF", "STAT", "fvar", "avar", "cvar", "VORG",
					"EBSC", "Silf", "Feat", "Glat", "Gloc", "Sill", "kerx", "TSIV", "BUSG", "SOPG", "clas", "MTfn":
					if _, highEnt := checkHighEntropy(tblBytes); highEnt {
						return nil, 0, false
					}
					if col := collapseRepeatedBytes(tblBytes, 16); len(col) >= minEntropyBytes && len(col) < len(tblBytes)*9/10 {
						if _, highEnt := checkHighEntropy(col); highEnt {
							return nil, 0, false
						}
					}
					if pCol := collapseRepeatedPeriodic(tblBytes, 32, 4); len(pCol) >= minEntropyBytes && len(pCol) < len(tblBytes)*9/10 {
						if _, highEnt := checkHighEntropy(pCol); highEnt {
							return nil, 0, false
						}
					}
					if hasConstantLanePlusHighEntResidual(tblBytes) {
						return nil, 0, false
					}
					if c0 := stripControlBytesForInspection(tblBytes); len(c0) >= minEntropyBytes && len(c0) < len(tblBytes)*9/10 {
						if _, highEnt := checkHighEntropyThresh(c0, 7.90); highEnt {
							return nil, 0, false
						}
					}
					if dom, ok := stripDominantByteIfOver(tblBytes, 20); ok && len(dom) >= minEntropyBytes {
						if checkMaxEntWindowIncompressible(dom, 7.90) {
							return nil, 0, false
						}
					}
					if hasLowDistIncompressible(tblBytes, 134, 5.80, 0.85) {
						return nil, 0, false
					}
				default:
					if hasConcealedHighEntropy(tblBytes) {
						return nil, 0, false
					}
				}
			}
		}
		switch tblTag {
		case "head":
			hasHead = tblLen >= 54
			headOff, headLen = tblOff, tblLen
		case "maxp":
			hasMaxp = true
			maxpOff, maxpLen = tblOff, tblLen
			hasOutlinesOrMetrics = true
		case "CFF ":
			hasCFF = true
			cffOff, cffLen = tblOff, tblLen
			hasOutlinesOrMetrics = true
		case "CFF2":
			hasCFF2 = true
			cff2Off, cff2Len = tblOff, tblLen
			hasOutlinesOrMetrics = true
		case "loca":
			hasLoca = true
			locaOff, locaLen = tblOff, tblLen
		case "glyf":
			hasGlyf = true
			glyfOff, glyfLen = tblOff, tblLen
		case "gvar":
			hasGvar = true
			gvarOff, gvarLen = tblOff, tblLen
		case "cvt ":
			hasCvt = true
			cvtOff, cvtLen = tblOff, tblLen
		case "fpgm":
			hasFpgm = true
			fpgmOff, fpgmLen = tblOff, tblLen
		}
	}
	if !hasHead || headLen < 54 || !hasOutlinesOrMetrics {
		return nil, 0, false
	}
	if len(aggSmall) >= minEntropyBytes && hasConcealedHighEntropy(aggSmall) {
		return nil, 0, false
	}
	if binary.BigEndian.Uint32(data[headOff+12:headOff+16]) != 0x5F0F3CF5 {
		return nil, 0, false
	}
	indexToLocFormat := binary.BigEndian.Uint16(data[headOff+50 : headOff+52])
	if indexToLocFormat > 1 {
		return nil, 0, false
	}
	maxpNumGlyphs := 0
	if hasMaxp {
		if maxpLen < 6 {
			return nil, 0, false
		}
		ver := binary.BigEndian.Uint32(data[maxpOff : maxpOff+4])
		if ver != 0x00005000 && ver != 0x00010000 {
			return nil, 0, false
		}
		maxpNumGlyphs = int(binary.BigEndian.Uint16(data[maxpOff+4 : maxpOff+6]))
	}
	if tag == 0x4F54544F && !hasCFF && !hasCFF2 {
		return nil, 0, false
	}
	if hasCFF {
		if !isValidCFFFont(data[cffOff : cffOff+cffLen]) {
			return nil, 0, false
		}
	}
	if hasCFF2 {
		if !isValidCFF2Font(data[cff2Off : cff2Off+cff2Len]) {
			return nil, 0, false
		}
	}
	var glyfInfo sfntGlyfInfo
	if hasGlyf {
		var gOK bool
		if !hasLoca {
			return nil, 0, false
		}
		glyfInfo, gOK = isValidSFNTGlyfWithLoca(data[glyfOff:glyfOff+glyfLen], data[locaOff:locaOff+locaLen], indexToLocFormat)
		if !gOK {
			return nil, 0, false
		}
	}
	if hasGvar {
		if !isValidSFNTGvar(data[gvarOff:gvarOff+gvarLen], maxpNumGlyphs, hasMaxp, glyfInfo.glyphNumPts) {
			return nil, 0, false
		}
	}
	if hasCvt && cvtLen >= minEntropyBytes {
		nonTrivialFpgm := false
		if hasFpgm && fpgmLen >= 20 {
			fpgmBytes := data[fpgmOff : fpgmOff+fpgmLen]
			fDist := distinctBytesCount(fpgmBytes)
			fpgmHighEnt := fpgmLen >= minEntropyBytes && (hasConcealedHighEntropy(fpgmBytes) || hasBitAgnosticIncompressible(fpgmBytes, 5.75, 0.80))
			hasFDEF := bytes.IndexByte(fpgmBytes, 0x2c) >= 0 && bytes.IndexByte(fpgmBytes, 0x2d) >= 0
			nonTrivialFpgm = fDist >= 8 && !fpgmHighEnt && hasFDEF && isValidTTBytecode(fpgmBytes)
		}
		glyfDiversityOK := hasGlyf &&
			glyfLen >= 8192 &&
			glyfInfo.outlineGlyphs >= 50 &&
			glyfInfo.uniqueGlyphHashes >= 120 &&
			glyfInfo.uniqueGlyphShapes >= 120 &&
			glyfInfo.aggCoordsLen >= 1024
		if cvtLen > 2048 || !glyfDiversityOK || !nonTrivialFpgm || (hasMaxp && maxpNumGlyphs < 50) {
			cvtBytes := data[cvtOff : cvtOff+cvtLen]
			if _, highEnt := checkHighEntropy(cvtBytes); highEnt {
				return nil, 0, false
			}
			if hasBitAgnosticIncompressible(cvtBytes, 6.20, 0.85) || hasLowDistIncompressible(cvtBytes, 134, 5.80, 0.85) {
				return nil, 0, false
			}
			if col := collapseRepeatedBytes(cvtBytes, 16); len(col) >= minEntropyBytes && len(col) < len(cvtBytes)*9/10 {
				if _, highEnt := checkHighEntropy(col); highEnt || hasBitAgnosticIncompressible(col, 6.20, 0.85) || hasLowDistIncompressible(col, 134, 5.80, 0.85) {
					return nil, 0, false
				}
			}
			if pCol := collapseRepeatedPeriodic(cvtBytes, 32, 4); len(pCol) >= minEntropyBytes && len(pCol) < len(cvtBytes)*9/10 {
				if checkMaxEntWindowIncompressible(pCol, entropyThreshold) || hasBitAgnosticIncompressible(pCol, 6.20, 0.85) || hasLowDistIncompressible(pCol, 134, 5.80, 0.85) {
					return nil, 0, false
				}
			}
			if hasConstantLanePlusHighEntResidual(cvtBytes) {
				return nil, 0, false
			}
			if c0 := stripControlBytesForInspection(cvtBytes); len(c0) >= minEntropyBytes && len(c0) < len(cvtBytes)*9/10 {
				if _, highEnt := checkHighEntropyThresh(c0, 7.75); highEnt || hasLowDistIncompressible(c0, 134, 6.40, 0.88) {
					return nil, 0, false
				}
			}
			if dom, ok := stripDominantByteIfOver(cvtBytes, 20); ok && len(dom) >= minEntropyBytes {
				if checkMaxEntWindowIncompressible(dom, 7.75) || hasLowDistIncompressible(dom, 134, 6.40, 0.88) {
					return nil, 0, false
				}
			}
		}
	}
	return spans, maxEnd, true
}

func isValidSFNTFont(data []byte) bool {
	spans, maxEnd, ok := isValidSFNTFontAt(data, 0, nil)
	if !ok {
		return false
	}
	if !checkGapsEntropy(data, spans, 0, int(maxEnd)) {
		return false
	}
	return uint64(len(data))-maxEnd <= 64
}

func isValidTTCFCollection(cur []byte) bool {
	if len(cur) < 16 || !bytes.HasPrefix(cur, []byte("ttcf")) {
		return false
	}
	ver := binary.BigEndian.Uint32(cur[4:8])
	numFonts := int(binary.BigEndian.Uint32(cur[8:12]))
	if (ver != 0x00010000 && ver != 0x00020000) || numFonts < 1 || numFonts > 64 || 12+4*numFonts > len(cur) {
		return false
	}
	ttcfHdrEnd := 12 + 4*numFonts
	dirSpans := make([]byteSpan, 0, numFonts+1)
	dirSpans = append(dirSpans, byteSpan{start: 0, end: ttcfHdrEnd})
	fontOffs := make([]int, numFonts)
	for fi := 0; fi < numFonts; fi++ {
		fo := int(binary.BigEndian.Uint32(cur[12+fi*4 : 16+fi*4]))
		if fo < ttcfHdrEnd || fo+12 > len(cur) {
			return false
		}
		nt := int(binary.BigEndian.Uint16(cur[fo+4 : fo+6]))
		if nt < 4 || nt > 128 || fo+12+nt*16 > len(cur) {
			return false
		}
		foEnd := fo + 12 + nt*16
		for _, ds := range dirSpans {
			if fo < ds.end && foEnd > ds.start {
				return false
			}
		}
		dirSpans = append(dirSpans, byteSpan{start: fo, end: foEnd})
		fontOffs[fi] = fo
	}
	maxEnd := uint64(ttcfHdrEnd)
	allSpans := []byteSpan{{start: 0, end: ttcfHdrEnd}}
	for _, fo := range fontOffs {
		spans, end, ok := isValidSFNTFontAt(cur, fo, dirSpans)
		if !ok {
			return false
		}
		allSpans = append(allSpans, spans...)
		if end > maxEnd {
			maxEnd = end
		}
	}
	return checkGapsEntropy(cur, allSpans, 0, int(maxEnd)) && uint64(len(cur))-maxEnd <= 64
}

type pdfType1Sections struct {
	plain []byte
	hdr   []byte
	tail  []byte
}

func isValidPDFType1Font(cleanDict, cur []byte) (pdfType1Sections, bool) {
	if !bytes.HasPrefix(cur, []byte("%!PS-AdobeFont")) && !bytes.HasPrefix(cur, []byte("%!FontType1")) {
		return pdfType1Sections{}, false
	}
	searchLim := min(len(cur), 64*1024)
	eexecPos := -1
	scanFrom := 0
	for scanFrom < searchLim {
		rel := bytes.Index(cur[scanFrom:searchLim], []byte("eexec"))
		if rel < 0 {
			break
		}
		cand := scanFrom + rel
		prevOK := cand == 0 || isPDFDelimiterOrWS(cur[cand-1])
		after := cand + len("eexec")
		nextOK := after < len(cur) && (cur[after] == ' ' || cur[after] == '\t' || cur[after] == '\r' || cur[after] == '\n')
		if prevOK && nextOK {
			eexecPos = cand
			break
		}
		scanFrom = cand + len("eexec")
	}

	hasHeaderKeyword := func(b []byte) bool {
		return bytes.Contains(b, []byte("/FontName")) ||
			bytes.Contains(b, []byte("FontDirectory")) ||
			bytes.Contains(b, []byte("definefont")) ||
			bytes.Contains(b, []byte("currentdict"))
	}

	if eexecPos < 0 {
		if looksBinary(cur) || !hasHeaderKeyword(cur) {
			return pdfType1Sections{}, false
		}
		_, highEnt := checkHighEntropy(cur)
		return pdfType1Sections{hdr: cur}, !highEnt
	}

	hdr := cur[:eexecPos]
	if looksBinary(hdr) || !hasHeaderKeyword(hdr) {
		return pdfType1Sections{}, false
	}
	if _, highEnt := checkHighEntropy(hdr); highEnt {
		return pdfType1Sections{}, false
	}

	bodyStart := eexecPos + len("eexec")
	if bodyStart+1 < len(cur) && cur[bodyStart] == '\r' && cur[bodyStart+1] == '\n' {
		bodyStart += 2
	} else if bodyStart < len(cur) {
		bodyStart++
	}
	if bodyStart >= len(cur) {
		return pdfType1Sections{}, false
	}

	bodyEnd := len(cur)
	var tail []byte
	if cm := bytes.LastIndex(cur[bodyStart:], []byte("cleartomark")); cm >= 0 {
		tail = cur[bodyStart+cm:]
		if looksBinary(tail) {
			return pdfType1Sections{}, false
		}
		if _, highEnt := checkHighEntropy(tail); highEnt {
			return pdfType1Sections{}, false
		}
		zEnd := bodyStart + cm
		for zEnd > bodyStart && (cur[zEnd-1] == '0' || cur[zEnd-1] == '\r' || cur[zEnd-1] == '\n' || cur[zEnd-1] == ' ' || cur[zEnd-1] == '\t') {
			zEnd--
		}
		bodyEnd = zEnd
	}
	if bodyEnd-bodyStart < 32 {
		return pdfType1Sections{}, false
	}
	rawBody := cur[bodyStart:bodyEnd]
	// Detect ASCII-hex eexec encoding vs binary eexec encoding.
	hexSample := rawBody[:min(len(rawBody), 64)]
	allHexOrWS := true
	hexDigits := 0
	for _, b := range hexSample {
		if isHexByte(b) {
			hexDigits++
			continue
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		allHexOrWS = false
		break
	}
	cipher := rawBody
	if allHexOrWS && hexDigits >= 32 {
		var hexOnly []byte
		for _, b := range rawBody {
			if isHexByte(b) {
				hexOnly = append(hexOnly, b)
			} else if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				allHexOrWS = false
				break
			}
		}
		if allHexOrWS && len(hexOnly) >= 64 {
			if len(hexOnly)%2 != 0 {
				hexOnly = hexOnly[:len(hexOnly)-1]
			}
			dec := make([]byte, hex.DecodedLen(len(hexOnly)))
			if _, err := hex.Decode(dec, hexOnly); err == nil {
				cipher = dec
			}
		}
	}
	if len(cipher) < 32 {
		return pdfType1Sections{}, false
	}
	r := uint32(55665)
	plain := make([]byte, len(cipher))
	for i, c := range cipher {
		plain[i] = c ^ byte(r>>8)
		r = ((uint32(c)+r)*52845 + 22719) & 0xFFFF
	}
	if !hasHighPrintableAscii(plain[4:min(len(plain), 68)]) {
		return pdfType1Sections{}, false
	}
	plainBody := plain[4:]
	if hasConcealedHighEntropy(plainBody) {
		return pdfType1Sections{}, false
	}
	return pdfType1Sections{plain: plain, hdr: hdr, tail: tail}, true
}

func undoPNGPredictorFilters(cur []byte, w, h int, rowBytes, bpp int) ([]byte, bool) {
	stride := rowBytes + 1
	if len(cur) != stride*h {
		return nil, false
	}
	raw := make([]byte, rowBytes*h)
	paeth := func(a, b, c byte) byte {
		p := int(a) + int(b) - int(c)
		pa := p - int(a)
		if pa < 0 {
			pa = -pa
		}
		pb := p - int(b)
		if pb < 0 {
			pb = -pb
		}
		pc := p - int(c)
		if pc < 0 {
			pc = -pc
		}
		if pa <= pb && pa <= pc {
			return a
		}
		if pb <= pc {
			return b
		}
		return c
	}
	for y := 0; y < h; y++ {
		srcRow := cur[y*stride : (y+1)*stride]
		filter := srcRow[0]
		if filter > 4 {
			return nil, false
		}
		dstRow := raw[y*rowBytes : (y+1)*rowBytes]
		var prevRow []byte
		if y > 0 {
			prevRow = raw[(y-1)*rowBytes : y*rowBytes]
		}
		for x := 0; x < rowBytes; x++ {
			var left, up, upLeft byte
			if x >= bpp {
				left = dstRow[x-bpp]
			}
			if prevRow != nil {
				up = prevRow[x]
				if x >= bpp {
					upLeft = prevRow[x-bpp]
				}
			}
			val := srcRow[x+1]
			switch filter {
			case 0:
				dstRow[x] = val
			case 1:
				dstRow[x] = val + left
			case 2:
				dstRow[x] = val + up
			case 3:
				dstRow[x] = val + byte((int(left)+int(up))/2)
			case 4:
				dstRow[x] = val + paeth(left, up, upLeft)
			}
		}
	}
	return raw, true
}

func hasRasterSpatialCorrelationRange(raw []byte, w, yStart, yEnd, nComp, bpc int, isIndexed bool) bool {
	rowBits := int64(w) * int64(nComp) * int64(bpc)
	rowBytes := int((rowBits + 7) / 8)
	h := yEnd - yStart
	if h <= 0 {
		return false
	}
	if bpc < 8 {
		var hTotal, hEq, vTotal, vEq int64
		for y := yStart; y < yEnd; y++ {
			row := raw[y*rowBytes : (y+1)*rowBytes]
			for x := 1; x < rowBytes; x++ {
				hTotal++
				if row[x] == row[x-1] {
					hEq++
				}
			}
			if y > yStart {
				prev := raw[(y-1)*rowBytes : y*rowBytes]
				for x := 0; x < rowBytes; x++ {
					vTotal++
					if row[x] == prev[x] {
						vEq++
					}
				}
			}
		}
		hOK := hTotal > 0 && float64(hEq)/float64(hTotal) >= 0.05
		vOK := vTotal > 0 && float64(vEq)/float64(vTotal) >= 0.05
		if (hTotal > 0 && !hOK) || (vTotal > 0 && !vOK) {
			return false
		}
		subStart := yStart * rowBytes
		subEnd := yEnd * rowBytes
		if subEnd-subStart >= minEntropyBytes {
			sub := raw[subStart:subEnd]
			if shannonEntropy(sub) >= 6.80 && zlibCompressedRatio(sub) >= 0.88 {
				return false
			}
		}
		return hOK || vOK
	}

	step := 1
	if bpc == 16 {
		step = 2
	}
	pixStride := nComp * step
	var hTotal, hSmall, hEq, vTotal, vSmall, vEq int64
	var hSmallLo, vSmallLo, hEqLo, vEqLo int64
	var hCont16, vCont16, hTotal2, hSmooth2_16, vTotal2, vSmooth2_16 int64
	var lowBytes []byte
	if bpc == 16 {
		lowBytes = make([]byte, 0, w*h*nComp)
	}
	for y := yStart; y < yEnd; y++ {
		row := raw[y*rowBytes : (y+1)*rowBytes]
		for x := 0; x < w; x++ {
			px := x * pixStride
			for c := 0; c < nComp; c++ {
				curVal := int(row[px+c*step])
				var curLo, cur16 int
				if bpc == 16 {
					curLo = int(row[px+c*step+1])
					lowBytes = append(lowBytes, byte(curLo))
					cur16 = (curVal << 8) | curLo
				}
				if x > 0 {
					leftVal := int(row[px-pixStride+c*step])
					hTotal++
					diff := curVal - leftVal
					if diff < 0 {
						diff = -diff
					}
					if diff <= 24 {
						hSmall++
					}
					if diff == 0 {
						hEq++
					}
					if bpc == 16 {
						leftLo := int(row[px-pixStride+c*step+1])
						dLo := curLo - leftLo
						if dLo < 0 {
							dLo = -dLo
						}
						if dLo <= 24 {
							hSmallLo++
						}
						if dLo == 0 {
							hEqLo++
						}
						left16 := (leftVal << 8) | leftLo
						d1H := cur16 - left16
						if d1H < 0 {
							d1H = -d1H
						}
						if d1H <= 2048 {
							hCont16++
						}
						if x >= 2 {
							left2_16 := (int(row[px-2*pixStride+c*2]) << 8) | int(row[px-2*pixStride+c*2+1])
							d2H := cur16 - 2*left16 + left2_16
							if d2H < 0 {
								d2H = -d2H
							}
							hTotal2++
							if d2H <= 24 {
								hSmooth2_16++
							}
						}
					}
				}
				if y > yStart {
					upVal := int(raw[(y-1)*rowBytes+px+c*step])
					vTotal++
					diff := curVal - upVal
					if diff < 0 {
						diff = -diff
					}
					if diff <= 24 {
						vSmall++
					}
					if diff == 0 {
						vEq++
					}
					if bpc == 16 {
						upLo := int(raw[(y-1)*rowBytes+px+c*step+1])
						dLo := curLo - upLo
						if dLo < 0 {
							dLo = -dLo
						}
						if dLo <= 24 {
							vSmallLo++
						}
						if dLo == 0 {
							vEqLo++
						}
						up16 := (upVal << 8) | upLo
						d1V := cur16 - up16
						if d1V < 0 {
							d1V = -d1V
						}
						if d1V <= 2048 {
							vCont16++
						}
						if y >= yStart+2 {
							up2_16 := (int(raw[(y-2)*rowBytes+px+c*2]) << 8) | int(raw[(y-2)*rowBytes+px+c*2+1])
							d2V := cur16 - 2*up16 + up2_16
							if d2V < 0 {
								d2V = -d2V
							}
							vTotal2++
							if d2V <= 24 {
								vSmooth2_16++
							}
						}
					}
				}
			}
		}
	}
	if bpc == 16 && len(lowBytes) >= minEntropyBytes {
		if _, lowEnt := checkHighEntropy(lowBytes); lowEnt {
			if isIndexed {
				hLoOK := hTotal == 0 || float64(hEqLo)/float64(hTotal) >= 0.05
				vLoOK := vTotal == 0 || float64(vEqLo)/float64(vTotal) >= 0.05
				if !hLoOK || !vLoOK {
					return false
				}
			} else {
				hLoOK := hTotal == 0 || float64(hSmallLo)/float64(hTotal) >= 0.25
				vLoOK := vTotal == 0 || float64(vSmallLo)/float64(vTotal) >= 0.25
				h16D2OK := hTotal == 0 || (hTotal2 > 0 && float64(hCont16)/float64(hTotal) >= 0.50 && float64(hSmooth2_16)/float64(hTotal2) >= 0.35)
				v16D2OK := vTotal == 0 || (vTotal2 > 0 && float64(vCont16)/float64(vTotal) >= 0.50 && float64(vSmooth2_16)/float64(vTotal2) >= 0.35)
				if !(hLoOK || h16D2OK) || !(vLoOK || v16D2OK) {
					return false
				}
			}
		}
	}
	if isIndexed {
		hOK := hTotal == 0 || float64(hEq)/float64(hTotal) >= 0.05
		vOK := vTotal == 0 || float64(vEq)/float64(vTotal) >= 0.05
		return hOK && vOK
	}
	hOK := hTotal == 0 || float64(hSmall)/float64(hTotal) >= 0.30
	vOK := vTotal == 0 || float64(vSmall)/float64(vTotal) >= 0.30
	return hOK && vOK
}

func adjSmallDiffRatio(b []byte, maxDiff int) float64 {
	if len(b) < 2 {
		return 1.0
	}
	small := 0
	for i := 1; i < len(b); i++ {
		d := int(b[i]) - int(b[i-1])
		if d < 0 {
			d = -d
		}
		if d <= maxDiff {
			small++
		}
	}
	return float64(small) / float64(len(b)-1)
}

func allSamePixelRow(row []byte, unit int) bool {
	if len(row) <= unit {
		return true
	}
	for i := unit; i < len(row); i++ {
		if row[i] != row[i%unit] {
			return false
		}
	}
	return true
}

func hasRasterSpatialCorrelation(raw []byte, w, h, nComp, bpc int, isIndexed bool) bool {
	rowBits := int64(w) * int64(nComp) * int64(bpc)
	rowBytes := int((rowBits + 7) / 8)
	if len(raw) != rowBytes*h || rowBytes <= 0 || h <= 0 {
		return false
	}
	// Check non-constant rows, non-constant columns, per-component channels, even/odd row sub-images,
	// and C0/dominant-byte-stripped residuals before any raw-entropy shortcut.
	pixUnit := 1
	if bpc >= 8 {
		pixUnit = max(1, (nComp*bpc+7)/8)
	}
	if nComp >= 2 && bpc >= 8 && !isIndexed {
		compUnit := bpc / 8
		compBuf := make([]byte, w*h*compUnit)
		for c := 0; c < nComp; c++ {
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					srcOff := y*rowBytes + x*pixUnit + c*compUnit
					dstOff := (y*w + x) * compUnit
					copy(compBuf[dstOff:dstOff+compUnit], raw[srcOff:srcOff+compUnit])
				}
			}
			if len(compBuf) >= minEntropyBytes {
				if _, cHigh := checkHighEntropy(compBuf); cHigh || bpc == 16 {
					if !hasRasterSpatialCorrelationRange(compBuf, w, 0, h, 1, bpc, false) {
						return false
					}
				}
			}
		}
	}
	if w >= 2 && bpc >= 8 && rowBytes == w*pixUnit {
		var nonConstColIdx []int
		for x := 0; x < w; x++ {
			colSame := true
			baseOff := x * pixUnit
			for y := 1; y < h; y++ {
				curOff := y*rowBytes + baseOff
				if !bytes.Equal(raw[curOff:curOff+pixUnit], raw[baseOff:baseOff+pixUnit]) {
					colSame = false
					break
				}
			}
			if !colSame {
				nonConstColIdx = append(nonConstColIdx, x)
			}
		}
		if len(nonConstColIdx) > 0 && len(nonConstColIdx) < w {
			ncW := len(nonConstColIdx)
			ncCols := make([]byte, ncW*h*pixUnit)
			for y := 0; y < h; y++ {
				for xi, x := range nonConstColIdx {
					srcOff := y*rowBytes + x*pixUnit
					dstOff := (y*ncW + xi) * pixUnit
					copy(ncCols[dstOff:dstOff+pixUnit], raw[srcOff:srcOff+pixUnit])
				}
			}
			if len(ncCols) >= minEntropyBytes {
				if _, ncHigh := checkHighEntropy(ncCols); ncHigh || bpc == 16 {
					if !hasRasterSpatialCorrelationRange(ncCols, ncW, 0, h, nComp, bpc, isIndexed) {
						return false
					}
				}
			}
		}
	}
	nonConstRaw := make([]byte, 0, len(raw))
	nonConstH := 0
	for y := 0; y < h; y++ {
		row := raw[y*rowBytes : (y+1)*rowBytes]
		if !allSamePixelRow(row, pixUnit) {
			nonConstRaw = append(nonConstRaw, row...)
			nonConstH++
		}
	}
	if len(nonConstRaw) >= minEntropyBytes {
		if _, ncHigh := checkHighEntropy(nonConstRaw); ncHigh || bpc == 16 {
			if !hasRasterSpatialCorrelationRange(nonConstRaw, w, 0, nonConstH, nComp, bpc, isIndexed) {
				return false
			}
		}
	}
	if h >= 4 {
		evenRows := make([]byte, 0, ((h+1)/2)*rowBytes)
		oddRows := make([]byte, 0, (h/2)*rowBytes)
		evenH, oddH := 0, 0
		for y := 0; y < h; y++ {
			row := raw[y*rowBytes : (y+1)*rowBytes]
			if y%2 == 0 {
				evenRows = append(evenRows, row...)
				evenH++
			} else {
				oddRows = append(oddRows, row...)
				oddH++
			}
		}
		if len(evenRows) >= minEntropyBytes {
			if _, eHigh := checkHighEntropy(evenRows); eHigh || bpc == 16 {
				if !hasRasterSpatialCorrelationRange(evenRows, w, 0, evenH, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
		if len(oddRows) >= minEntropyBytes {
			if _, oHigh := checkHighEntropy(oddRows); oHigh || bpc == 16 {
				if !hasRasterSpatialCorrelationRange(oddRows, w, 0, oddH, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
	}
	if w >= 4 && bpc >= 8 && rowBytes == w*pixUnit {
		evenW := (w + 1) / 2
		oddW := w / 2
		evenCols := make([]byte, 0, evenW*h*pixUnit)
		oddCols := make([]byte, 0, oddW*h*pixUnit)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				px := raw[y*rowBytes+x*pixUnit : y*rowBytes+(x+1)*pixUnit]
				if x%2 == 0 {
					evenCols = append(evenCols, px...)
				} else {
					oddCols = append(oddCols, px...)
				}
			}
		}
		if len(evenCols) >= minEntropyBytes {
			if _, eHigh := checkHighEntropy(evenCols); eHigh || bpc == 16 {
				if !hasRasterSpatialCorrelationRange(evenCols, evenW, 0, h, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
		if len(oddCols) >= minEntropyBytes {
			if _, oHigh := checkHighEntropy(oddCols); oHigh || bpc == 16 {
				if !hasRasterSpatialCorrelationRange(oddCols, oddW, 0, h, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
	}
	if bpc <= 8 {
		if isIndexed && bpc == 8 && rowBytes == w*pixUnit && w >= 2 && h >= 2 {
			// Deduplicate identical adjacent rows/cols and check remaining non-equal transitions.
			var keptRows []int
			for y := 0; y < h; y++ {
				if y == 0 || !bytes.Equal(raw[y*rowBytes:(y+1)*rowBytes], raw[(y-1)*rowBytes:y*rowBytes]) {
					keptRows = append(keptRows, y)
				}
			}
			var keptCols []int
			for x := 0; x < w; x++ {
				if x == 0 {
					keptCols = append(keptCols, x)
					continue
				}
				sameAsPrev := true
				for _, ry := range keptRows {
					base := ry * rowBytes
					if !bytes.Equal(raw[base+x*pixUnit:base+(x+1)*pixUnit], raw[base+(x-1)*pixUnit:base+x*pixUnit]) {
						sameAsPrev = false
						break
					}
				}
				if !sameAsPrev {
					keptCols = append(keptCols, x)
				}
			}
			dedupW := len(keptCols)
			dedupH := len(keptRows)
			dedup := make([]byte, 0, dedupW*dedupH*pixUnit)
			for _, ry := range keptRows {
				base := ry * rowBytes
				for _, cx := range keptCols {
					dedup = append(dedup, raw[base+cx*pixUnit:base+(cx+1)*pixUnit]...)
				}
			}
			if len(dedup) >= minEntropyBytes && dedupW >= 2 && dedupH >= 2 {
				var dhEq, dhTot, dvEq, dvTot int
				nonEq := make([]byte, 0, dedupW*dedupH)
				for y := 0; y < dedupH; y++ {
					for x := 0; x < dedupW; x++ {
						cur := dedup[y*dedupW+x]
						sameL := x > 0 && cur == dedup[y*dedupW+x-1]
						sameU := y > 0 && cur == dedup[(y-1)*dedupW+x]
						if x > 0 {
							dhTot++
							if sameL {
								dhEq++
							}
						}
						if y > 0 {
							dvTot++
							if sameU {
								dvEq++
							}
						}
						if !sameL && !sameU {
							nonEq = append(nonEq, cur)
						}
					}
				}
				hEqRatio := 1.0
				if dhTot > 0 {
					hEqRatio = float64(dhEq) / float64(dhTot)
				}
				vEqRatio := 1.0
				if dvTot > 0 {
					vEqRatio = float64(dvEq) / float64(dvTot)
				}
				if (hEqRatio < 0.05 || vEqRatio < 0.05) && len(nonEq) >= minEntropyBytes {
					if shannonEntropy(nonEq) >= 7.80 && zlibCompressedRatio(nonEq) >= 0.92 {
						return false
					}
				}
			}
		}
		stripped := stripControlBytesForInspection(raw)
		if len(stripped) >= minEntropyBytes && len(stripped) < len(raw)*4/5 {
			if _, sHigh := checkHighEntropy(stripped); sHigh && adjSmallDiffRatio(stripped, 24) < 0.35 {
				return false
			}
		}
		if dom, ok := stripDominantByteIfOver(raw, 20); ok && len(dom) >= minEntropyBytes && len(dom) < len(raw)*4/5 {
			if _, dHigh := checkHighEntropy(dom); dHigh && zlibCompressedRatio(dom) >= 0.85 && adjSmallDiffRatio(dom, 24) < 0.35 {
				return false
			}
		}
		if domK, ok := stripTopKBytes(raw, 8, 4, 25); ok && len(domK) >= minEntropyBytes && len(domK) < len(raw)*4/5 {
			if _, dHigh := checkHighEntropy(domK); dHigh && zlibCompressedRatio(domK) >= 0.85 {
				if (!isIndexed && adjSmallDiffRatio(domK, 24) < 0.35) || (isIndexed && adjSmallDiffRatio(domK, 0) < 0.05) {
					return false
				}
			}
		}
		if narrow, ok := stripNarrowBandBytes(raw, 32, 0.40); ok && len(narrow) >= minEntropyBytes {
			if shannonEntropy(narrow) >= 6.40 && zlibCompressedRatio(narrow) >= 0.85 && seqAvgDiff(narrow) >= 55 {
				if (!isIndexed && adjSmallDiffRatio(narrow, 24) < 0.35) || (isIndexed && adjSmallDiffRatio(narrow, 0) < 0.05) {
					return false
				}
			}
		}
		if multi, ok := stripTopKMultiPad(raw, 32, 0.40); ok && len(multi) >= minEntropyBytes {
			if shannonEntropy(multi) >= 6.40 && zlibCompressedRatio(multi) >= 0.85 && seqAvgDiff(multi) >= 55 {
				if (!isIndexed && adjSmallDiffRatio(multi, 24) < 0.35) || (isIndexed && adjSmallDiffRatio(multi, 0) < 0.05) {
					return false
				}
			}
		}
		if pCol := collapseRepeatedPeriodic(raw, 32, 4); len(pCol) >= minEntropyBytes && len(pCol) < len(raw)*4/5 {
			if _, pHigh := checkHighEntropy(pCol); pHigh && zlibCompressedRatio(pCol) >= 0.85 {
				if (!isIndexed && adjSmallDiffRatio(pCol, 24) < 0.35) || (isIndexed && adjSmallDiffRatio(pCol, 0) < 0.05) {
					return false
				}
			}
		}
	} else if bpc == 16 && !isIndexed {
		lowBytes := make([]byte, 0, len(raw)/2)
		for i := 1; i < len(raw); i += 2 {
			lowBytes = append(lowBytes, raw[i])
		}
		if len(lowBytes) >= minEntropyBytes {
			strippedLo := stripControlBytesForInspection(lowBytes)
			if len(strippedLo) >= minEntropyBytes && len(strippedLo) < len(lowBytes)*4/5 {
				if _, sHigh := checkHighEntropy(strippedLo); sHigh && zlibCompressedRatio(strippedLo) >= 0.85 && adjSmallDiffRatio(strippedLo, 24) < 0.35 {
					return false
				}
			}
			if domLo, ok := stripDominantByteIfOver(lowBytes, 20); ok && len(domLo) >= minEntropyBytes && len(domLo) < len(lowBytes)*4/5 {
				if _, dHigh := checkHighEntropy(domLo); dHigh && zlibCompressedRatio(domLo) >= 0.85 && adjSmallDiffRatio(domLo, 24) < 0.35 {
					return false
				}
			}
			if domLoK, ok := stripTopKBytes(lowBytes, 8, 4, 25); ok && len(domLoK) >= minEntropyBytes && len(domLoK) < len(lowBytes)*4/5 {
				if _, dHigh := checkHighEntropy(domLoK); dHigh && zlibCompressedRatio(domLoK) >= 0.85 && adjSmallDiffRatio(domLoK, 24) < 0.35 {
					return false
				}
			}
		}
	}
	if _, highEnt := checkHighEntropy(raw); !highEnt && bpc != 16 {
		return true
	}
	if !hasRasterSpatialCorrelationRange(raw, w, 0, h, nComp, bpc, isIndexed) {
		return false
	}
	// Check horizontal bands (>= 256B each) so 33% zeros + 67% CSPRNG cannot pass global averages.
	rowsPerBand := max(1, (minEntropyBytes+rowBytes-1)/rowBytes)
	if h >= rowsPerBand*2 {
		for y0 := 0; y0 < h; y0 += rowsPerBand {
			y1 := min(h, y0+rowsPerBand)
			band := raw[y0*rowBytes : y1*rowBytes]
			if len(band) < minEntropyBytes {
				break
			}
			_, bandHighEnt := checkHighEntropy(band)
			if bandHighEnt && !hasRasterSpatialCorrelationRange(raw, w, y0, y1, nComp, bpc, isIndexed) {
				return false
			}
			if bpc == 16 && !bandHighEnt {
				// Still verify lowBytes entropy + correlation on 16-bit bands.
				if !hasRasterSpatialCorrelationRange(raw, w, y0, y1, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
	}
	// Check vertical column bands (>= 256B each) so 36% left-margin + 64% right-margin CSPRNG cannot pass global averages.
	if bpc >= 8 && rowBytes == w*pixUnit {
		colsPerBand := max(1, (minEntropyBytes+h*pixUnit-1)/(h*pixUnit))
		if w >= colsPerBand*2 {
			colBandBuf := make([]byte, 0, colsPerBand*h*pixUnit)
			for x0 := 0; x0 < w; x0 += colsPerBand {
				x1 := min(w, x0+colsPerBand)
				colBandBuf = colBandBuf[:0]
				for y := 0; y < h; y++ {
					colBandBuf = append(colBandBuf, raw[y*rowBytes+x0*pixUnit:y*rowBytes+x1*pixUnit]...)
				}
				if len(colBandBuf) < minEntropyBytes {
					break
				}
				_, bandHighEnt := checkHighEntropy(colBandBuf)
				if (bandHighEnt || bpc == 16) && !hasRasterSpatialCorrelationRange(colBandBuf, x1-x0, 0, h, nComp, bpc, isIndexed) {
					return false
				}
			}
		}
	}
	return true
}

func isValidPDFBinaryAssetStream(cleanDict, cur []byte) (isValid bool, type1 pdfType1Sections) {
	if len(cur) == 0 {
		return false, pdfType1Sections{}
	}
	if hasPDFDictKey(cleanDict, "Length1") && (bytes.HasPrefix(cur, []byte("%!PS-AdobeFont")) || bytes.HasPrefix(cur, []byte("%!FontType1"))) {
		if t1, ok := isValidPDFType1Font(cleanDict, cur); ok {
			return true, t1
		}
	}

	// 1. Valid embedded font stream (/Length1 or /Subtype /Type1C|/CIDFontType0C|/OpenType).
	// Checked before hasHighPrintableAscii(stripped) because legitimate SFNT/CFF fonts
	// (e.g. NotoSansGunjalaGondi) can have UTF-16 `name` + ASCII `String INDEX` > 85% in the first 4KB.
	if hasPDFDictKey(cleanDict, "Length1") || hasPDFDictNameValue(cleanDict, "Subtype", "Type1C", "CIDFontType0C", "OpenType") {
		if isValidSFNTFont(cur) {
			return true, pdfType1Sections{}
		}
		if isValidTTCFCollection(cur) {
			return true, pdfType1Sections{}
		}
		if hasPDFDictNameValue(cleanDict, "Subtype", "Type1C", "CIDFontType0C") {
			if isValidCFFFont(cur) {
				return true, pdfType1Sections{}
			}
		}
	}

	// 2. Valid /ICCBased profile stream (/N or /Alternate + valid ICC header & tag table).
	// Checked before hasHighPrintableAscii(stripped) because small profiles (e.g. AdobeRGB1998.icc)
	// have ASCII headers/tags and C0 padding yielding > 85% printable ASCII after C0 stripping.
	if (hasPDFDictKey(cleanDict, "N") || hasPDFDictKey(cleanDict, "Alternate")) && isValidICCProfileHeaderAndTags(cur) {
		return true, pdfType1Sections{}
	}

	stripped := stripControlBytesForInspection(cur)
	if hasHighPrintableAscii(stripped) {
		return false, pdfType1Sections{}
	}

	// 3. Valid /Subtype /Image raster XObject.
	if hasPDFDictNameValue(cleanDict, "Subtype", "Image") {
		wm := pdfWidthRe.FindSubmatch(cleanDict)
		hm := pdfHeightRe.FindSubmatch(cleanDict)
		if len(wm) == 2 && len(hm) == 2 {
			w, wErr := strconv.Atoi(string(wm[1]))
			h, hErr := strconv.Atoi(string(hm[1]))
			if wErr == nil && hErr == nil && w > 0 && h > 0 && w <= 65536 && h <= 65536 {
				isMask := bytes.Contains(cleanDict, []byte("/ImageMask true"))
				bpc := 0
				if bm := pdfBPCRe.FindSubmatch(cleanDict); len(bm) == 2 {
					bpc, _ = strconv.Atoi(string(bm[1]))
				} else if isMask {
					bpc = 1
				}
				if bpc == 1 || bpc == 2 || bpc == 4 || bpc == 8 || bpc == 16 {
					hasPredictor := false
					if pm := pdfPredictorRe.FindSubmatch(cleanDict); len(pm) == 2 {
						pred, _ := strconv.Atoi(string(pm[1]))
						hasPredictor = pred >= 10
					}
					cs, hasCS := extractPDFDictNameAfterKey(cleanDict, "ColorSpace")
					isIndexed := cs == "Indexed" || pdfIndexedCSRe.Match(cleanDict)
					matchesComp := func(nComp int) bool {
						rowBits := int64(w) * int64(nComp) * int64(bpc)
						rowBytes := (rowBits + 7) / 8
						expected := rowBytes * int64(h)
						if int64(len(cur)) == expected {
							return hasRasterSpatialCorrelation(cur, w, h, nComp, bpc, isIndexed)
						}
						if hasPredictor && int64(len(cur)) == (rowBytes+1)*int64(h) {
							bpp := max(1, (nComp*bpc+7)/8)
							rawPixels, ok := undoPNGPredictorFilters(cur, w, h, int(rowBytes), bpp)
							if !ok {
								return false
							}
							return hasRasterSpatialCorrelation(rawPixels, w, h, nComp, bpc, isIndexed)
						}
						return false
					}
					switch {
					case isMask || isIndexed || cs == "DeviceGray" || cs == "CalGray":
						return matchesComp(1), pdfType1Sections{}
					case cs == "DeviceRGB" || cs == "CalRGB":
						return matchesComp(3), pdfType1Sections{}
					case cs == "DeviceCMYK":
						return matchesComp(4), pdfType1Sections{}
					case !hasCS || hasPDFDictKey(cleanDict, "ColorSpace"):
						for nComp := 1; nComp <= 4; nComp++ {
							if matchesComp(nComp) {
								return true, pdfType1Sections{}
							}
						}
					}
				}
			}
		}
	}

	return false, pdfType1Sections{}
}

func decodePDFASCIIHex(raw []byte) ([]byte, bool) {
	hexBuf := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b == '>' {
			break
		}
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' || b == 0 {
			continue
		}
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return nil, false
		}
		hexBuf = append(hexBuf, b)
	}
	if len(hexBuf)%2 == 1 {
		hexBuf = append(hexBuf, '0')
	}
	out := make([]byte, hex.DecodedLen(len(hexBuf)))
	if _, err := hex.Decode(out, hexBuf); err != nil {
		return nil, false
	}
	return out, true
}

func decodePDFASCII85(raw []byte, maxBytes int64) ([]byte, bool, bool) {
	trimmed := bytes.TrimSpace(raw)
	trimmed = bytes.TrimPrefix(trimmed, []byte("<~"))
	if eod := bytes.Index(trimmed, []byte("~>")); eod >= 0 {
		trimmed = trimmed[:eod]
	}
	limit := min(int64(defaultArchiveMaxEntryBytes), maxBytes)
	if limit <= 0 {
		return nil, true, false
	}
	dec := ascii85.NewDecoder(bytes.NewReader(trimmed))
	out, err := io.ReadAll(io.LimitReader(dec, limit+1))
	if err != nil {
		return nil, false, false
	}
	if int64(len(out)) > limit {
		return nil, true, false
	}
	return out, false, true
}

func isValidJ2KCodestream(cs []byte) bool {
	if len(cs) < 48 || cs[0] != 0xFF || cs[1] != 0x4F || cs[2] != 0xFF || cs[3] != 0x51 {
		return false
	}
	pos := 2
	seenSIZ := false
	seenCOD := false
	seenQCD := false
	seenEOC := false
	hasTilePart := false
	for pos+2 <= len(cs) {
		if cs[pos] != 0xFF {
			return false
		}
		m := cs[pos+1]
		if m == 0xD9 { // EOC
			pos += 2
			seenEOC = true
			break
		}
		if m == 0x90 { // SOT: start of tile-part
			if pos+12 > len(cs) {
				return false
			}
			lsot := int(binary.BigEndian.Uint16(cs[pos+2 : pos+4]))
			if lsot != 10 {
				return false
			}
			psot := int(binary.BigEndian.Uint32(cs[pos+6 : pos+10]))
			if psot != 0 && (psot < 14 || pos+psot > len(cs)) {
				return false
			}
			tpLimit := len(cs)
			if psot > 0 {
				tpLimit = pos + psot
			}
			pos += 12
			foundSOD := false
			for pos+2 <= tpLimit {
				if cs[pos] != 0xFF {
					return false
				}
				tm := cs[pos+1]
				if tm == 0x93 { // SOD
					pos += 2
					foundSOD = true
					break
				}
				if pos+4 > tpLimit {
					return false
				}
				segLen := int(binary.BigEndian.Uint16(cs[pos+2 : pos+4]))
				if segLen < 2 || pos+2+segLen > tpLimit {
					return false
				}
				if tm == 0x64 { // COM
					if len(cs[pos+4:pos+2+segLen]) >= 16 && hasHighPrintableAscii(cs[pos+4:pos+2+segLen]) {
						return false
					}
				}
				pos += 2 + segLen
			}
			if !foundSOD {
				return false
			}
			dataEnd := tpLimit
			if psot == 0 {
				if tpLimit < 2 || cs[tpLimit-2] != 0xFF || cs[tpLimit-1] != 0xD9 {
					return false
				}
				dataEnd = tpLimit - 2
			}
			if dataEnd <= pos {
				return false
			}
			tpData := cs[pos:dataEnd]
			if (len(tpData) >= 32 && hasHighPrintableAscii(tpData)) || len(extractPrintableTextRuns(tpData, 48)) > 0 {
				return false
			}
			ffCount := 0
			for i := 0; i < len(tpData); {
				if tpData[i] != 0xFF {
					i++
					continue
				}
				ffCount++
				if i+1 >= len(tpData) {
					return false
				}
				nxt := tpData[i+1]
				if nxt < 0x90 {
					i += 2
					continue
				}
				if nxt == 0x91 && i+6 <= len(tpData) && tpData[i+2] == 0x00 && tpData[i+3] == 0x04 { // SOP
					i += 6
					continue
				}
				if nxt == 0x92 { // EPH
					i += 2
					continue
				}
				return false
			}
			if len(tpData) >= 4096 && ffCount == 0 && shannonEntropy(tpData) >= 7.5 {
				return false
			}
			hasTilePart = true
			pos = dataEnd
			continue
		}
		if m < 0x30 || (m >= 0x30 && m <= 0x3F) || m == 0x4F || m == 0x92 || m == 0x93 {
			pos += 2
			continue
		}
		if pos+4 > len(cs) {
			return false
		}
		segLen := int(binary.BigEndian.Uint16(cs[pos+2 : pos+4]))
		if segLen < 2 || pos+2+segLen > len(cs) {
			return false
		}
		segPayload := cs[pos+4 : pos+2+segLen]
		switch m {
		case 0x51: // SIZ
			if segLen < 41 {
				return false
			}
			xsiz := binary.BigEndian.Uint32(segPayload[2:6])
			ysiz := binary.BigEndian.Uint32(segPayload[6:10])
			xtsiz := binary.BigEndian.Uint32(segPayload[18:22])
			ytsiz := binary.BigEndian.Uint32(segPayload[22:26])
			csiz := int(binary.BigEndian.Uint16(segPayload[34:36]))
			if xsiz == 0 || ysiz == 0 || xtsiz == 0 || ytsiz == 0 || csiz == 0 || segLen != 38+3*csiz {
				return false
			}
			seenSIZ = true
		case 0x52: // COD
			if segLen < 12 {
				return false
			}
			seenCOD = true
		case 0x5C: // QCD
			if segLen < 4 {
				return false
			}
			seenQCD = true
		case 0x64: // COM
			if len(segPayload) >= 16 && hasHighPrintableAscii(segPayload) {
				return false
			}
			if hasConcealedHighEntropy(segPayload) || hasBitAgnosticIncompressible(segPayload, 6.40, 0.88) {
				return false
			}
		default:
			if hasConcealedHighEntropy(segPayload) || hasBitAgnosticIncompressible(segPayload, 6.40, 0.88) {
				return false
			}
		}
		pos += 2 + segLen
	}
	return seenSIZ && seenCOD && seenQCD && hasTilePart && seenEOC && pos == len(cs)
}

func isValidJP2OrJ2KStream(b []byte) bool {
	if len(b) >= 4 && b[0] == 0xFF && b[1] == 0x4F && b[2] == 0xFF && b[3] == 0x51 {
		return isValidJ2KCodestream(b)
	}
	if len(b) < 24 || !bytes.Equal(b[:12], []byte{0x00, 0x00, 0x00, 0x0C, 'j', 'P', ' ', ' ', 0x0D, 0x0A, 0x87, 0x0A}) {
		return false
	}
	off := 12
	seenFtyp := false
	seenJp2h := false
	seenIhdr := false
	seenJp2c := false
	for off+8 <= len(b) {
		lbox := uint64(binary.BigEndian.Uint32(b[off : off+4]))
		boxType := string(b[off+4 : off+8])
		hdrLen := uint64(8)
		if lbox == 1 {
			if off+16 > len(b) {
				return false
			}
			lbox = binary.BigEndian.Uint64(b[off+8 : off+16])
			hdrLen = 16
		} else if lbox == 0 {
			lbox = uint64(len(b) - off)
		}
		if lbox < hdrLen || lbox > uint64(len(b)-off) {
			return false
		}
		payload := b[off+int(hdrLen) : off+int(lbox)]
		switch boxType {
		case "ftyp":
			if len(payload) < 8 {
				return false
			}
			brand := string(payload[:4])
			if brand != "jp2 " && brand != "jpx " {
				return false
			}
			seenFtyp = true
		case "jp2h":
			seenJp2h = true
			subOff := 0
			for subOff+8 <= len(payload) {
				sl := binary.BigEndian.Uint32(payload[subOff : subOff+4])
				st := string(payload[subOff+4 : subOff+8])
				if sl < 8 || subOff+int(sl) > len(payload) {
					return false
				}
				sp := payload[subOff+8 : subOff+int(sl)]
				if st == "ihdr" {
					if len(sp) != 14 {
						return false
					}
					ih := binary.BigEndian.Uint32(sp[0:4])
					iw := binary.BigEndian.Uint32(sp[4:8])
					nc := binary.BigEndian.Uint16(sp[8:10])
					if iw == 0 || ih == 0 || nc == 0 {
						return false
					}
					seenIhdr = true
				} else if st == "colr" {
					if len(sp) < 3 {
						return false
					}
					if sp[0] == 2 || sp[0] == 3 {
						prof := sp[3:]
						if len(prof) < 128 || !isValidICCProfileHeaderAndTags(prof) {
							return false
						}
					} else if hasConcealedHighEntropy(sp) || hasBitAgnosticIncompressible(sp, 6.40, 0.88) {
						return false
					}
				} else if hasConcealedHighEntropy(sp) || hasBitAgnosticIncompressible(sp, 6.40, 0.88) {
					return false
				}
				subOff += int(sl)
			}
			if subOff != len(payload) {
				return false
			}
		case "jp2c":
			if !isValidJ2KCodestream(payload) {
				return false
			}
			seenJp2c = true
		case "rreq", "xml ", "uuid", "uinf", "ulst", "url ":
			if len(payload) >= minEntropyBytes && (hasConcealedHighEntropy(payload) || hasBitAgnosticIncompressible(payload, 6.40, 0.88)) {
				return false
			}
		default:
			if len(payload) >= minEntropyBytes && (hasConcealedHighEntropy(payload) || hasBitAgnosticIncompressible(payload, 6.40, 0.88)) {
				return false
			}
		}
		off += int(lbox)
	}
	return seenFtyp && seenJp2h && seenIhdr && seenJp2c && off == len(b)
}

type pdfStreamSpan struct {
	start int
	end   int
}

type pdfValidationResult struct {
	valid       bool
	bombed      bool
	streamSpans []pdfStreamSpan
}

func inspectPDFNonStreamBytes(
	ctx context.Context,
	virtualPath string,
	data []byte,
	spans []pdfStreamSpan,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if res == nil || len(data) == 0 {
		return
	}
	// Collect all non-stream regions, excluding only the standard short binary comment on line 2 (%[\x80-\xff]+).
	skipStart, skipEnd := 0, 0
	if nl := bytes.IndexAny(data, "\r\n"); nl >= 0 && nl < 32 {
		line2Start := nl + 1
		if data[nl] == '\r' && line2Start < len(data) && data[line2Start] == '\n' {
			line2Start++
		}
		if line2Start < len(data) && data[line2Start] == '%' {
			line2End := line2Start
			for line2End < len(data) && line2End-line2Start <= 16 && data[line2End] != '\n' && data[line2End] != '\r' {
				line2End++
			}
			if line2End-line2Start <= 16 && line2End < len(data) && (data[line2End] == '\n' || data[line2End] == '\r') {
				hasHigh := false
				for _, b := range data[line2Start+1 : line2End] {
					if b >= 0x80 {
						hasHigh = true
						break
					}
				}
				if hasHigh {
					skipStart = line2Start
					skipEnd = line2End
				}
			}
		}
	}

	var nonStream bytes.Buffer
	appendSlice := func(s, e int) {
		if s >= e || s < 0 || e > len(data) {
			return
		}
		if skipEnd > skipStart && s < skipEnd && e > skipStart {
			if s < skipStart {
				nonStream.Write(data[s:skipStart])
			}
			if e > skipEnd {
				nonStream.Write(data[skipEnd:e])
			}
			return
		}
		nonStream.Write(data[s:e])
	}

	cur := 0
	for _, sp := range spans {
		if sp.start > cur {
			appendSlice(cur, sp.start)
			nonStream.WriteByte('\n')
		}
		if sp.end > cur {
			cur = sp.end
		}
	}
	if cur < len(data) {
		appendSlice(cur, len(data))
	}

	nsBytes := nonStream.Bytes()
	if len(nsBytes) == 0 {
		return
	}
	if ent, flagged := checkHighEntropy(nsBytes); flagged {
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.high-entropy",
			domain.SeverityHigh,
			virtualPath,
			"high-entropy payload outside PDF streams",
			map[string]any{
				"layer":         "L4_CONCEALMENT",
				"technique":     "high_entropy",
				"chunk_suffix":  "#pdf_nonstream",
				"shannon_bits":  math.Round(ent*1000) / 1000,
				"payload_bytes": len(nsBytes),
			},
			fmt.Sprintf("pdf_nonstream_entropy:%.3f:%d", ent, len(nsBytes)),
		))
	}
	stripped := stripControlBytesForInspection(nsBytes)
	if len(stripped) >= minEntropyBytes && len(stripped) < len(nsBytes)*9/10 {
		if ent, flagged := checkHighEntropy(stripped); flagged {
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.high-entropy",
				domain.SeverityHigh,
				virtualPath,
				"high-entropy C0-diluted payload outside PDF streams",
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "high_entropy",
					"chunk_suffix":  "#pdf_nonstream",
					"shannon_bits":  math.Round(ent*1000) / 1000,
					"payload_bytes": len(stripped),
				},
				fmt.Sprintf("pdf_nonstream_stripped_entropy:%.3f:%d", ent, len(stripped)),
			))
		}
	}
	emitCredentialFindings(virtualPath, nsBytes, res)
	if len(stripped) > 0 && len(stripped) != len(nsBytes) {
		emitCredentialFindings(virtualPath, stripped, res)
		if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
			subPath := virtualPath + "#pdf_nonstream"
			res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
				VirtualPath:    subPath,
				Data:           extracted,
				InArchive:      inArchive,
				InEncoded:      inEncoded,
				ExtractedMedia: true,
			})
			emitCredentialFindings(subPath, extracted, res)
			if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
				inspectEncodedPayloads(ctx, subPath, extracted, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
			}
		}
	}
}

func validateAndInspectPDFStreams(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) pdfValidationResult {
	pos := 0
	streamIdx := 0
	var spans []pdfStreamSpan
	var pdfTotalInflated int64

	remainingPDFBudget := func() int64 {
		rem := int64(defaultArchiveMaxTotalBytes) - pdfTotalInflated
		if budget != nil {
			budgetRem := budget.MaxTotalInflatedBytes - budget.TotalInflated
			if budgetRem < rem {
				rem = budgetRem
			}
		}
		return rem
	}
	chargePDFBudget := func(n int64) {
		pdfTotalInflated += n
		if budget != nil {
			budget.TotalInflated += n
		}
	}
	failBomb := func() pdfValidationResult {
		if res != nil {
			b := budget
			if b == nil {
				b = newDefaultArchiveBudget()
			}
			emitArchiveBomb(virtualPath, "pdf", "inflated_bytes_exceeded", b, res)
		}
		return pdfValidationResult{valid: false, bombed: true, streamSpans: spans}
	}

	for pos < len(data) {
		rel := bytes.Index(data[pos:], []byte("stream"))
		if rel < 0 {
			break
		}
		absIdx := pos + rel
		// Require a PDF token boundary before "stream" (not "endstream" or "/ObjStm").
		if absIdx > 0 {
			prev := data[absIdx-1]
			if prev != '\n' && prev != '\r' && prev != ' ' && prev != '\t' && prev != '>' {
				pos = absIdx + len("stream")
				continue
			}
		}
		after := absIdx + len("stream")
		if after >= len(data) || (data[after] != '\n' && data[after] != '\r') {
			pos = after
			continue
		}
		streamStart := after + 1
		if data[after] == '\r' && streamStart < len(data) && data[streamStart] == '\n' {
			streamStart++
		}

		dictStart := max(0, absIdx-2048)
		dictSlice := data[dictStart:absIdx]
		if objEnd := findLastPDFObjHeaderEnd(dictSlice); objEnd >= 0 {
			dictSlice = dictSlice[objEnd:]
		}
		cleanDict := stripPDFCommentsAndStrings(dictSlice)

		streamEnd := -1
		nextPos := -1
		if !pdfLengthRefRe.Match(cleanDict) {
			if m := pdfLengthDirectRe.FindSubmatch(cleanDict); len(m) == 2 {
				length, convErr := strconv.Atoi(string(m[1]))
				if convErr == nil && length >= 0 && length <= len(data)-streamStart {
					cand := bytes.TrimLeft(data[streamStart+length:], "\r\n \t")
					if bytes.HasPrefix(cand, []byte("endstream")) {
						streamEnd = streamStart + length
						offsetIntoCand := len(data[streamStart+length:]) - len(cand)
						nextPos = streamStart + length + offsetIntoCand + len("endstream")
					}
				}
			}
		}
		if streamEnd < 0 {
			endRel := bytes.Index(data[streamStart:], []byte("endstream"))
			if endRel < 0 {
				return pdfValidationResult{valid: false, streamSpans: spans}
			}
			streamEnd = streamStart + endRel
			if streamEnd >= streamStart+2 && data[streamEnd-2] == '\r' && data[streamEnd-1] == '\n' {
				streamEnd -= 2
			} else if streamEnd >= streamStart+1 && (data[streamEnd-1] == '\n' || data[streamEnd-1] == '\r') {
				streamEnd--
			}
			nextPos = streamStart + endRel + len("endstream")
		}
		streamBody := data[streamStart:streamEnd]
		spans = append(spans, pdfStreamSpan{start: streamStart, end: nextPos})

		var filters []string
		filterParseFailed := false
		hasFilterKey := hasPDFDictKey(cleanDict, "Filter")
		if fm := pdfFilterBlockRe.FindSubmatch(cleanDict); len(fm) == 3 {
			if len(fm[1]) > 0 {
				for _, nm := range pdfFilterNameRe.FindAllSubmatch(fm[1], -1) {
					if len(nm) == 2 {
						decodedName, ok := decodePDFName(string(nm[1]))
						if !ok {
							filterParseFailed = true
							break
						}
						filters = append(filters, decodedName)
					}
				}
			} else if len(fm[2]) > 0 {
				decodedName, ok := decodePDFName(string(fm[2]))
				if !ok {
					filterParseFailed = true
				} else {
					filters = append(filters, decodedName)
				}
			}
		}

		if !hasFilterKey && len(filters) == 0 {
			if _, highEnt := checkHighEntropy(streamBody); highEnt {
				return pdfValidationResult{valid: false, streamSpans: spans}
			}
			if res != nil {
				inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#pdfstream[%d]", streamIdx), streamBody, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
		} else if filterParseFailed || (hasFilterKey && len(filters) == 0) {
			if res != nil {
				inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#pdfstream[%d]", streamIdx), streamBody, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
			}
		} else {
			cur := streamBody
			fullyDecoded := true
			isValidatedImage := false
			for _, f := range filters {
				switch f {
				case "ASCIIHexDecode":
					if looksBinary(cur) {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					dec, ok := decodePDFASCIIHex(cur)
					if !ok {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					cur = dec
				case "ASCII85Decode":
					if looksBinary(cur) {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					rem := remainingPDFBudget()
					dec, bombed, ok := decodePDFASCII85(cur, rem)
					if bombed {
						return failBomb()
					}
					if !ok {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					chargePDFBudget(int64(len(dec)))
					cur = dec
				case "FlateDecode":
					rem := remainingPDFBudget()
					if rem <= 0 {
						return failBomb()
					}
					limit := min(int64(defaultArchiveMaxEntryBytes), rem)
					zr, err := zlib.NewReader(bytes.NewReader(cur))
					if err != nil {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					dec, readErr := io.ReadAll(io.LimitReader(zr, limit+1))
					_ = zr.Close()
					if readErr != nil {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					if int64(len(dec)) > limit {
						return failBomb()
					}
					chargePDFBudget(int64(len(dec)))
					cur = dec
				case "DCTDecode":
					if !isValidJPEGStructure(cur) {
						return pdfValidationResult{valid: false, streamSpans: spans}
					}
					if res != nil {
						inspectJPEGMetadataSegments(ctx, fmt.Sprintf("%s#pdfdct[%d]", virtualPath, streamIdx), cur, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					}
					isValidatedImage = true
				case "JPXDecode":
					if isValidJP2OrJ2KStream(cur) {
						isValidatedImage = true
					} else {
						fullyDecoded = false
					}
				default:
					fullyDecoded = false
				}
				if isValidatedImage || !fullyDecoded {
					break
				}
			}

			if res != nil && !isValidatedImage {
				subPath := fmt.Sprintf("%s#pdfstream[%d]", virtualPath, streamIdx)
				if fullyDecoded {
					isValidAsset, type1 := isValidPDFBinaryAssetStream(cleanDict, cur)
					isValidType1Font := isValidAsset && hasPDFDictKey(cleanDict, "Length1") &&
						(bytes.HasPrefix(cur, []byte("%!PS-AdobeFont")) || bytes.HasPrefix(cur, []byte("%!FontType1")))
					inspectType1Part := func(bufPath string, bufData []byte) {
						if len(bufData) == 0 {
							return
						}
						if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
							inspectRecursiveL4Opts(ctx, bufPath, bufData, archiveDepth, decodeDepth+1, inArchive, true, false, true, budget, decodeRemaining, res)
							return
						}
						stripped := stripControlBytesForInspection(bufData)
						emitCredentialFindings(bufPath, bufData, res)
						if len(stripped) > 0 && len(stripped) != len(bufData) {
							emitCredentialFindings(bufPath, stripped, res)
						}
						if !looksBinary(bufData) {
							res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
								VirtualPath:    bufPath,
								Data:           bufData,
								InArchive:      inArchive,
								InEncoded:      true,
								ExtractedMedia: true,
							})
						} else if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
							res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
								VirtualPath:    bufPath,
								Data:           extracted,
								InArchive:      inArchive,
								InEncoded:      true,
								ExtractedMedia: true,
							})
							emitCredentialFindings(bufPath, extracted, res)
						}
					}
					if !isValidAsset && (len(cur) >= minEntropyBytes || hasPDFDictNameValue(cleanDict, "Subtype", "Type1C", "CIDFontType0C", "OpenType")) &&
						(hasPDFDictKey(cleanDict, "Length1") ||
							hasPDFDictNameValue(cleanDict, "Subtype", "Type1C", "CIDFontType0C", "OpenType") ||
							hasPDFDictKey(cleanDict, "N") ||
							hasPDFDictKey(cleanDict, "Alternate")) {
						res.Findings = append(res.Findings, makeConcealmentFinding(
							"ip.l4.magic-byte-mismatch",
							domain.SeverityHigh,
							subPath,
							"corrupt, spoofed, or high-entropy binary asset inside PDF stream",
							map[string]any{
								"layer":         "L4_CONCEALMENT",
								"technique":     "invalid_pdf_asset_stream",
								"payload_bytes": len(cur),
							},
							fmt.Sprintf("invalid_pdf_asset:%d", len(cur)),
						))
					}
					if isValidType1Font {
						if len(type1.plain) > 4 {
							inspectType1Part(subPath+"#type1_eexec", type1.plain[4:])
							inspectType1Part(subPath+"#type1_header", type1.hdr)
							inspectType1Part(subPath+"#type1_tail", type1.tail)
						} else {
							inspectType1Part(subPath, cur)
						}
					} else if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
						inspectRecursiveL4Opts(ctx, subPath, cur, archiveDepth, decodeDepth+1, inArchive, true, isValidAsset, true, budget, decodeRemaining, res)
					} else if isValidAsset {
						stripped := stripControlBytesForInspection(cur)
						emitCredentialFindings(subPath, cur, res)
						if len(stripped) > 0 && len(stripped) != len(cur) {
							emitCredentialFindings(subPath, stripped, res)
						}
						if extracted := extractPrintableTextRuns(stripped, 32); len(extracted) > 0 {
							res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
								VirtualPath:    subPath,
								Data:           extracted,
								InArchive:      inArchive,
								InEncoded:      true,
								ExtractedMedia: true,
							})
							emitCredentialFindings(subPath, extracted, res)
						}
					} else {
						inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#pdfstream[%d]", streamIdx), cur, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
					}
				} else {
					inspectAncillaryPayload(ctx, virtualPath, fmt.Sprintf("#pdfstream[%d]", streamIdx), cur, archiveDepth, decodeDepth, inArchive, inEncoded, budget, decodeRemaining, res)
				}
			}
		}

		streamIdx++
		pos = nextPos
	}
	return pdfValidationResult{valid: true, streamSpans: spans}
}

func readSLEB128Bounded(b []byte, maxBytes int) (int, bool) {
	for i := 0; i < maxBytes && i < len(b); i++ {
		if b[i]&0x80 == 0 {
			return i + 1, true
		}
	}
	return 0, false
}

func skipWASMInitExpr(b []byte) (int, bool) {
	off := 0
	for off < len(b) {
		op := b[off]
		off++
		switch op {
		case 0x0b:
			return off, true
		case 0x41:
			adv, ok := readSLEB128Bounded(b[off:], 5)
			if !ok {
				return 0, false
			}
			off += adv
		case 0x42:
			adv, ok := readSLEB128Bounded(b[off:], 10)
			if !ok {
				return 0, false
			}
			off += adv
		case 0x43:
			if off+4 > len(b) {
				return 0, false
			}
			off += 4
		case 0x44:
			if off+8 > len(b) {
				return 0, false
			}
			off += 8
		case 0x23, 0xd2:
			_, adv, ok := readULEB128(b[off:])
			if !ok {
				return 0, false
			}
			off += adv
		case 0xd0:
			if off+1 > len(b) {
				return 0, false
			}
			off++
		default:
			return 0, false
		}
	}
	return 0, false
}

func parseWASMTypeSection(b []byte) bool {
	count, off, ok := readULEB128(b)
	if !ok {
		return false
	}
	for i := uint64(0); i < count; i++ {
		if off >= len(b) || b[off] != 0x60 {
			return false
		}
		off++
		paramCount, adv, ok := readULEB128(b[off:])
		if !ok {
			return false
		}
		off += adv
		if paramCount > uint64(len(b)-off) {
			return false
		}
		off += int(paramCount)
		resCount, adv, ok := readULEB128(b[off:])
		if !ok {
			return false
		}
		off += adv
		if resCount > uint64(len(b)-off) {
			return false
		}
		off += int(resCount)
	}
	return off == len(b)
}

func parseWASMFunctionSection(b []byte) (uint64, bool) {
	count, off, ok := readULEB128(b)
	if !ok {
		return 0, false
	}
	for i := uint64(0); i < count; i++ {
		_, adv, ok := readULEB128(b[off:])
		if !ok {
			return 0, false
		}
		off += adv
	}
	return count, off == len(b)
}

func parseWASMExportSection(b []byte) bool {
	count, off, ok := readULEB128(b)
	if !ok {
		return false
	}
	for i := uint64(0); i < count; i++ {
		nameLen, adv, ok := readULEB128(b[off:])
		if !ok {
			return false
		}
		off += adv
		if nameLen > 1024 || nameLen > uint64(len(b)-off) {
			return false
		}
		nameBytes := b[off : off+int(nameLen)]
		if !utf8.Valid(nameBytes) {
			return false
		}
		for _, ch := range nameBytes {
			if ch < 0x20 || ch == 0x7f {
				return false
			}
		}
		off += int(nameLen)
		if off >= len(b) || b[off] > 3 {
			return false
		}
		off++
		_, idxAdv, ok := readULEB128(b[off:])
		if !ok {
			return false
		}
		off += idxAdv
	}
	return off == len(b)
}

func isWASMSec10Concealed(secBody []byte) bool {
	if len(secBody) < minEntropyBytes {
		return false
	}
	if _, highEnt := checkHighEntropy(secBody); highEnt {
		return true
	}
	if isBitAgnosticIncompressibleHighEntropy(secBody, true) {
		return true
	}
	if hasConstantLanePlusHighEntResidual(secBody) {
		return true
	}
	if c0 := stripControlBytesForInspection(secBody); len(c0) >= minEntropyBytes && len(c0) < len(secBody)*9/10 {
		if checkMaxEntWindowIncompressible(c0, entropyThreshold) || isBitAgnosticIncompressibleHighEntropy(c0, true) {
			return true
		}
	}
	if pCol := collapseRepeatedPeriodic(secBody, 32, 4); len(pCol) >= minEntropyBytes && len(pCol) < len(secBody)*9/10 {
		if checkMaxEntWindowIncompressible(pCol, entropyThreshold) || isBitAgnosticIncompressibleHighEntropy(pCol, true) {
			return true
		}
	}
	if isTopKPadDilutedHighEntropy(secBody, true) {
		return true
	}
	return false
}

func parseWASMCodeSection(b []byte) (funcCount uint64, totalCodeBytes int, substantial bool, ok bool) {
	funcCount, totalCodeBytes, substantial, _, ok = parseWASMCodeSectionWithConceal(b, true)
	return funcCount, totalCodeBytes, substantial, ok
}

func parseWASMCodeSectionWithConceal(b []byte, checkConceal bool) (funcCount uint64, totalCodeBytes int, substantial bool, concealed bool, ok bool) {
	var off int
	funcCount, off, ok = readULEB128(b)
	if !ok {
		return 0, 0, false, false, false
	}
	var seen [256]bool
	nopCount := 0
	uniqueBodies := make(map[uint64]struct{}, min(int(funcCount), 4096))
	var funcsWithCallOrCtrl uint64
	for i := uint64(0); i < funcCount; i++ {
		bodySize, adv, ok := readULEB128(b[off:])
		if !ok || bodySize < 1 {
			return 0, 0, false, false, false
		}
		off += adv
		if bodySize > uint64(len(b)-off) {
			return 0, 0, false, false, false
		}
		body := b[off : off+int(bodySize)]
		off += int(bodySize)
		if body[len(body)-1] != 0x0b {
			return 0, 0, false, false, false
		}
		h := uint64(14695981039346656037)
		for _, x := range body {
			h ^= uint64(x)
			h *= 1099511628211
		}
		uniqueBodies[h] = struct{}{}
		localGroups, boff, ok := readULEB128(body)
		if !ok {
			return 0, 0, false, false, false
		}
		for lg := uint64(0); lg < localGroups; lg++ {
			_, ladv, ok := readULEB128(body[boff:])
			if !ok {
				return 0, 0, false, false, false
			}
			boff += ladv
			if boff >= len(body) {
				return 0, 0, false, false, false
			}
			boff++
		}
		if boff >= len(body) {
			return 0, 0, false, false, false
		}
		instr := body[boff:]
		totalCodeBytes += len(instr)
		hasCallOrCtrl := false
		for _, op := range instr {
			seen[op] = true
			if op == 0x01 {
				nopCount++
			}
			if op == 0x10 || op == 0x11 || op == 0x02 || op == 0x03 || op == 0x04 || op == 0x0c || op == 0x0d {
				hasCallOrCtrl = true
			}
		}
		if hasCallOrCtrl {
			funcsWithCallOrCtrl++
		}
	}
	if off != len(b) {
		return 0, 0, false, false, false
	}
	distinctBytes := 0
	for _, s := range seen {
		if s {
			distinctBytes++
		}
	}
	if checkConceal {
		concealed = isWASMSec10Concealed(b)
	}
	substantial = funcCount >= 32 &&
		len(uniqueBodies) >= 16 &&
		funcsWithCallOrCtrl*2 >= funcCount &&
		totalCodeBytes >= 16384 &&
		distinctBytes >= 16 &&
		nopCount*4 < totalCodeBytes &&
		!concealed
	return funcCount, totalCodeBytes, substantial, concealed, true
}

func parseWASMDataSection(b []byte) ([][]byte, bool) {
	segCount, off, ok := readULEB128(b)
	if !ok {
		return nil, false
	}
	if segCount > 100000 {
		return nil, false
	}
	segs := make([][]byte, 0, min(int(segCount), 64))
	for i := uint64(0); i < segCount; i++ {
		mode, adv, ok := readULEB128(b[off:])
		if !ok || mode > 2 {
			return nil, false
		}
		off += adv
		if mode == 2 {
			_, madv, ok := readULEB128(b[off:])
			if !ok {
				return nil, false
			}
			off += madv
		}
		if mode == 0 || mode == 2 {
			eadv, ok := skipWASMInitExpr(b[off:])
			if !ok {
				return nil, false
			}
			off += eadv
		}
		dataLen, dadv, ok := readULEB128(b[off:])
		if !ok {
			return nil, false
		}
		off += dadv
		if dataLen > uint64(len(b)-off) {
			return nil, false
		}
		segs = append(segs, b[off:off+int(dataLen)])
		off += int(dataLen)
	}
	return segs, off == len(b)
}

func isValidWASMStructure(data []byte) bool {
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}) {
		return false
	}
	if len(data) == 8 {
		return true
	}
	off := 8
	hasStandardSection := false
	var hasFunc3, hasCode10 bool
	var funcCount3, funcCount10 uint64
	for off < len(data) {
		secID := data[off]
		off++
		if secID > 12 {
			return false
		}
		if secID >= 1 {
			hasStandardSection = true
		}
		secLen, adv, ok := readULEB128(data[off:])
		if !ok {
			return false
		}
		off += adv
		if secLen > uint64(len(data)-off) {
			return false
		}
		secBody := data[off : off+int(secLen)]
		switch secID {
		case 0:
			nameLen, nameAdv, nameOK := readULEB128(secBody)
			if !nameOK || nameLen > secLen-uint64(nameAdv) {
				return false
			}
			if !utf8.Valid(secBody[nameAdv : nameAdv+int(nameLen)]) {
				return false
			}
		case 1:
			if !parseWASMTypeSection(secBody) {
				return false
			}
		case 3:
			cnt, fok := parseWASMFunctionSection(secBody)
			if !fok {
				return false
			}
			hasFunc3 = true
			funcCount3 = cnt
		case 7:
			if !parseWASMExportSection(secBody) {
				return false
			}
		case 10:
			cnt, _, _, _, cok := parseWASMCodeSectionWithConceal(secBody, false)
			if !cok {
				return false
			}
			hasCode10 = true
			funcCount10 = cnt
		case 11:
			if _, dok := parseWASMDataSection(secBody); !dok {
				return false
			}
		case 12:
			_, dcAdv, dcOK := readULEB128(secBody)
			if !dcOK || dcAdv != len(secBody) {
				return false
			}
		}
		off += int(secLen)
	}
	if hasFunc3 && hasCode10 && funcCount3 != funcCount10 {
		return false
	}
	return off == len(data) && hasStandardSection
}

func isCRC32Table1024Endian(b []byte, bigEndian bool) bool {
	if len(b) != 1024 {
		return false
	}
	readU32 := func(idx int) uint32 {
		if bigEndian {
			return binary.BigEndian.Uint32(b[idx*4 : idx*4+4])
		}
		return binary.LittleEndian.Uint32(b[idx*4 : idx*4+4])
	}
	if readU32(0) != 0 {
		return false
	}
	t1, t2, t3 := readU32(1), readU32(2), readU32(3)
	if t1 == 0 || (t1^t2) != t3 {
		return false
	}
	var t [256]uint32
	nonZero := 0
	for i := 1; i < 256; i++ {
		t[i] = readU32(i)
		if t[i] != 0 {
			nonZero++
		}
	}
	if nonZero < 200 {
		return false
	}
	matches := 0
	total := 0
	for i := 1; i < 256; i++ {
		lo := i & 0x0f
		hi := i & 0xf0
		if lo != 0 && hi != 0 {
			total++
			if (t[lo] ^ t[hi]) == t[i] {
				matches++
			}
		}
		j := (i*37 + 13) & 0xff
		total++
		if (t[i] ^ t[j]) == t[i^j] {
			matches++
		}
	}
	return total > 0 && matches*10 >= total*9
}

func gf28Mul(a, b byte) byte {
	var res byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			res ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return res
}

func gf28Pow(a byte, exp int) byte {
	res := byte(1)
	for exp > 0 {
		if exp&1 != 0 {
			res = gf28Mul(res, a)
		}
		a = gf28Mul(a, a)
		exp >>= 1
	}
	return res
}

var (
	wasmAESSBox0  [256]byte
	wasmAESSBox1  [256]byte
	wasmAESTe0    [256]uint32
	wasmAEStd0    [256]uint32
	wasmSHA512KLE [640]byte
	wasmSHA512KBE [640]byte

	wasmP256Params     = elliptic.P256().Params()
	wasmP256R          = new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 256), wasmP256Params.P)
	wasmP256BaseBy64   map[[64]byte]int
	wasmP256BaseAffine [43]struct {
		x, y *big.Int
	}
	wasmP256BaseB0 [256]bool
	wasmP256BaseB1 [256]bool
)

func encodeP256MontLE(x, y *big.Int) [64]byte {
	var out [64]byte
	xm := new(big.Int).Mul(x, wasmP256R)
	xm.Mod(xm, wasmP256Params.P)
	ym := new(big.Int).Mul(y, wasmP256R)
	ym.Mod(ym, wasmP256Params.P)
	var xb, yb [32]byte
	xm.FillBytes(xb[:])
	ym.FillBytes(yb[:])
	for k := 0; k < 32; k++ {
		out[k] = xb[31-k]
		out[32+k] = yb[31-k]
	}
	return out
}

func init() {
	// Derive AES forward/inverse S-boxes and Te0/Td0 tables mathematically from GF(2^8) 0x11b.
	for i := 0; i < 256; i++ {
		q := gf28Pow(byte(i), 254)
		s := q ^ bits.RotateLeft8(q, 1) ^ bits.RotateLeft8(q, 2) ^ bits.RotateLeft8(q, 3) ^ bits.RotateLeft8(q, 4) ^ 0x63
		wasmAESSBox0[i] = s
		wasmAESSBox1[s] = byte(i)
	}
	for i := 0; i < 256; i++ {
		s := wasmAESSBox0[i]
		s2 := gf28Mul(s, 2)
		s3 := s2 ^ s
		wasmAESTe0[i] = (uint32(s2) << 24) | (uint32(s) << 16) | (uint32(s) << 8) | uint32(s3)

		inv := wasmAESSBox1[i]
		se := gf28Mul(inv, 0x0e)
		s9 := gf28Mul(inv, 0x09)
		sd := gf28Mul(inv, 0x0d)
		sb := gf28Mul(inv, 0x0b)
		wasmAEStd0[i] = (uint32(se) << 24) | (uint32(s9) << 16) | (uint32(sd) << 8) | uint32(sb)
	}

	// Derive SHA-512 round constants K[0..79] mathematically from cube roots of first 80 primes.
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	primeCount := 0
	for p := int64(2); primeCount < 80; p++ {
		isPrime := true
		for d := int64(2); d*d <= p; d++ {
			if p%d == 0 {
				isPrime = false
				break
			}
		}
		if !isPrime {
			continue
		}
		target := new(big.Int).Lsh(big.NewInt(p), 192)
		x := new(big.Int).Lsh(one, 67)
		x2 := new(big.Int)
		q := new(big.Int)
		next := new(big.Int)
		for {
			x2.Mul(x, x)
			q.Div(target, x2)
			next.Mul(x, two)
			next.Add(next, q)
			next.Div(next, three)
			if next.Cmp(x) >= 0 {
				break
			}
			x.Set(next)
		}
		cube := new(big.Int)
		for {
			cube.Mul(x, x)
			cube.Mul(cube, x)
			if cube.Cmp(target) <= 0 {
				break
			}
			x.Sub(x, one)
		}
		for {
			xp1 := new(big.Int).Add(x, one)
			cube.Mul(xp1, xp1)
			cube.Mul(cube, xp1)
			if cube.Cmp(target) > 0 {
				break
			}
			x.Set(xp1)
		}
		kVal := x.Uint64()
		binary.LittleEndian.PutUint64(wasmSHA512KLE[primeCount*8:(primeCount+1)*8], kVal)
		binary.BigEndian.PutUint64(wasmSHA512KBE[primeCount*8:(primeCount+1)*8], kVal)
		primeCount++
	}

	// Derive P-256 Montgomery generator base points B_i = [2^(6i)]G for i=0..42 from elliptic.P256().Params().
	wasmP256BaseBy64 = make(map[[64]byte]int, 43)
	bx := new(big.Int).Set(wasmP256Params.Gx)
	by := new(big.Int).Set(wasmP256Params.Gy)
	for t := 0; t < 43; t++ {
		wasmP256BaseAffine[t].x = new(big.Int).Set(bx)
		wasmP256BaseAffine[t].y = new(big.Int).Set(by)
		key := encodeP256MontLE(bx, by)
		wasmP256BaseBy64[key] = t
		wasmP256BaseB0[key[0]] = true
		wasmP256BaseB1[key[1]] = true
		for d := 0; d < 6; d++ {
			bx, by = wasmP256Params.Double(bx, by)
		}
	}
}

func isAESTeOrTd4096(b []byte) bool {
	if len(b) < 4096 {
		return false
	}
	matchTable := func(bigEnd bool, tbl *[256]uint32) bool {
		for i := 0; i < 256; i++ {
			var w0, w1, w2, w3 uint32
			if bigEnd {
				w0 = binary.BigEndian.Uint32(b[i*4 : i*4+4])
				w1 = binary.BigEndian.Uint32(b[1024+i*4 : 1024+i*4+4])
				w2 = binary.BigEndian.Uint32(b[2048+i*4 : 2048+i*4+4])
				w3 = binary.BigEndian.Uint32(b[3072+i*4 : 3072+i*4+4])
			} else {
				w0 = binary.LittleEndian.Uint32(b[i*4 : i*4+4])
				w1 = binary.LittleEndian.Uint32(b[1024+i*4 : 1024+i*4+4])
				w2 = binary.LittleEndian.Uint32(b[2048+i*4 : 2048+i*4+4])
				w3 = binary.LittleEndian.Uint32(b[3072+i*4 : 3072+i*4+4])
			}
			if w0 != tbl[i] {
				return false
			}
			r1 := (w0 >> 8) | (w0 << 24)
			r2 := (w0 >> 16) | (w0 << 16)
			l1 := (w0 << 8) | (w0 >> 24)
			if !((w1 == r1 && w2 == r2 && w3 == l1) || (w1 == l1 && w2 == r2 && w3 == r1)) {
				return false
			}
		}
		return true
	}
	return matchTable(false, &wasmAESTe0) || matchTable(false, &wasmAEStd0) ||
		matchTable(true, &wasmAESTe0) || matchTable(true, &wasmAEStd0)
}

func p256MontTableSpan(seg []byte) int {
	if len(seg) < 2048 || !wasmP256BaseB0[seg[0]] || !wasmP256BaseB1[seg[1]] {
		return 0
	}
	var key [64]byte
	copy(key[:], seg[:64])
	tblIdx, ok := wasmP256BaseBy64[key]
	if !ok {
		return 0
	}
	span := 0
	for t := tblIdx; t < 43 && span+2048 <= len(seg); t++ {
		bx, by := wasmP256BaseAffine[t].x, wasmP256BaseAffine[t].y
		curX, curY := new(big.Int).Set(bx), new(big.Int).Set(by)
		exp0 := encodeP256MontLE(curX, curY)
		if !bytes.Equal(seg[span:span+64], exp0[:]) {
			break
		}
		subOK := true
		for j := 1; j < 32; j++ {
			curX, curY = wasmP256Params.Add(curX, curY, bx, by)
			expJ := encodeP256MontLE(curX, curY)
			if !bytes.Equal(seg[span+j*64:span+(j+1)*64], expJ[:]) {
				subOK = false
				break
			}
		}
		if !subOK {
			break
		}
		span += 2048
	}
	return span
}

func isPow10U128Block(b []byte, bigEnd bool) int {
	// Checks consecutive 16-byte normalized powers of 10: u128[i+1] ≈ norm(10 * u128[i]).
	if len(b) < 256 {
		return 0
	}
	readPair := func(off int) (hi, lo uint64) {
		if bigEnd {
			hi = binary.BigEndian.Uint64(b[off : off+8])
			lo = binary.BigEndian.Uint64(b[off+8 : off+16])
		} else {
			hi = binary.LittleEndian.Uint64(b[off : off+8])
			lo = binary.LittleEndian.Uint64(b[off+8 : off+16])
		}
		return hi, lo
	}
	toTrue := func(hi, lo uint64, negLo bool) (uint64, uint64) {
		if negLo && lo != 0 {
			return hi - 1, -lo
		}
		return hi, lo
	}
	maxEntries := len(b) / 16
	bestSpan := 0
	for _, negLo := range []bool{true, false} {
		hiRaw0, loRaw0 := readPair(0)
		hiPrev, loPrev := toTrue(hiRaw0, loRaw0, negLo)
		if hiPrev>>63 == 0 {
			continue
		}
		matched := 1
		for i := 1; i < maxEntries; i++ {
			hiRaw, loRaw := readPair(i * 16)
			hiCur, loCur := toTrue(hiRaw, loRaw, negLo)
			if hiCur>>63 == 0 {
				break
			}
			pHi, pLo := bits.Mul64(hiPrev, 10)
			qHi, qLo := bits.Mul64(loPrev, 10)
			mid, carry := bits.Add64(pLo, qHi, 0)
			top := pHi + carry
			var expHi, expLo uint64
			if top >= 8 {
				expHi = (top << 60) | (mid >> 4)
				expLo = (mid << 60) | (qLo >> 4)
			} else {
				expHi = (top << 61) | (mid >> 3)
				expLo = (mid << 61) | (qLo >> 3)
			}
			var dHi, dLo, borrow uint64
			if hiCur > expHi || (hiCur == expHi && loCur >= expLo) {
				dLo, borrow = bits.Sub64(loCur, expLo, 0)
				dHi, _ = bits.Sub64(hiCur, expHi, borrow)
			} else {
				dLo, borrow = bits.Sub64(expLo, loCur, 0)
				dHi, _ = bits.Sub64(expHi, hiCur, borrow)
			}
			if dHi != 0 || dLo > 16 {
				break
			}
			matched++
			hiPrev, loPrev = hiCur, loCur
		}
		if matched >= 16 && matched*16 > bestSpan {
			bestSpan = matched * 16
		}
	}
	return bestSpan
}

func removeCRC32Tables(seg []byte) []byte {
	if len(seg) < 256 {
		return seg
	}
	var out []byte
	copied := 0
	off := 0
	for off+256 <= len(seg) {
		if off+1024 <= len(seg) &&
			seg[off] == 0 && seg[off+1] == 0 && seg[off+2] == 0 && seg[off+3] == 0 &&
			(seg[off+4] != 0 || seg[off+5] != 0 || seg[off+6] != 0 || seg[off+7] != 0) &&
			(isCRC32Table1024Endian(seg[off:off+1024], false) || isCRC32Table1024Endian(seg[off:off+1024], true)) {
			out = append(out, seg[copied:off]...)
			off += 1024
			copied = off
			continue
		}
		if (seg[off] == wasmAESSBox0[0] && bytes.Equal(seg[off:off+256], wasmAESSBox0[:])) ||
			(seg[off] == wasmAESSBox1[0] && bytes.Equal(seg[off:off+256], wasmAESSBox1[:])) {
			out = append(out, seg[copied:off]...)
			off += 256
			copied = off
			continue
		}
		if off+640 <= len(seg) &&
			((seg[off] == wasmSHA512KLE[0] && bytes.Equal(seg[off:off+640], wasmSHA512KLE[:])) ||
				(seg[off] == wasmSHA512KBE[0] && bytes.Equal(seg[off:off+640], wasmSHA512KBE[:]))) {
			out = append(out, seg[copied:off]...)
			off += 640
			copied = off
			continue
		}
		if off+4096 <= len(seg) && isAESTeOrTd4096(seg[off:off+4096]) {
			out = append(out, seg[copied:off]...)
			off += 4096
			copied = off
			continue
		}
		if off+2048 <= len(seg) {
			if span := p256MontTableSpan(seg[off:]); span >= 2048 {
				out = append(out, seg[copied:off]...)
				off += span
				copied = off
				continue
			}
		}
		if off+256 <= len(seg) {
			if seg[off+7]&0x80 != 0 || seg[off]&0x80 != 0 {
				if span := isPow10U128Block(seg[off:], false); span >= 256 {
					out = append(out, seg[copied:off]...)
					off += span
					copied = off
					continue
				}
				if span := isPow10U128Block(seg[off:], true); span >= 256 {
					out = append(out, seg[copied:off]...)
					off += span
					copied = off
					continue
				}
			}
		}
		off++
	}
	if copied == 0 {
		return seg
	}
	out = append(out, seg[copied:]...)
	return out
}

func zlibCompressedRatio(b []byte) float64 {
	if len(b) == 0 {
		return 1.0
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return float64(buf.Len()) / float64(len(b))
}

func hasConstantLanePlusHighEntResidual(b []byte) bool {
	return hasConstantLanePlusHighEntResidualThresh(b, entropyThreshold)
}

func hasConstantLanePlusHighEntResidualThresh(b []byte, thresh float64) bool {
	for stride := 2; stride <= 16; stride++ {
		minRows := 64
		effThresh := thresh
		if stride > 8 {
			minRows = 32
			effThresh = max(thresh, 7.55)
		}
		if len(b) < stride*minRows || len(b) < minEntropyBytes {
			continue
		}
		lim := len(b) - (len(b) % stride)
		var laneSeen [16][256]bool
		var laneDistinct [16]int
		for i := 0; i < lim; i += stride {
			for l := 0; l < stride; l++ {
				v := b[i+l]
				if !laneSeen[l][v] {
					laneSeen[l][v] = true
					laneDistinct[l]++
				}
			}
		}
		constLanes := 0
		for l := 0; l < stride; l++ {
			if laneDistinct[l] <= 2 {
				constLanes++
			}
		}
		if constLanes == 0 || constLanes == stride {
			continue
		}
		residual := make([]byte, 0, (lim/stride)*(stride-constLanes))
		for i := 0; i < lim; i += stride {
			for l := 0; l < stride; l++ {
				if laneDistinct[l] > 2 {
					residual = append(residual, b[i+l])
				}
			}
		}
		if len(residual) >= minEntropyBytes {
			if _, highEnt := checkHighEntropyThresh(residual, effThresh); highEnt && zlibCompressedRatio(residual) >= 0.88 && hasHighDeltaEntropy(residual) {
				return true
			}
			if rs := stripControlBytesForInspection(residual); len(rs) >= minEntropyBytes && len(rs) < len(residual)*9/10 {
				if _, highEnt := checkHighEntropyThresh(rs, max(effThresh, 7.55)); highEnt && zlibCompressedRatio(rs) >= 0.90 && hasHighDeltaEntropy(rs) {
					return true
				}
			}
			if rd, ok := stripDominantByteIfOver(residual, 20); ok && len(rd) >= minEntropyBytes {
				if _, highEnt := checkHighEntropyThresh(rd, max(effThresh, 7.88)); highEnt && zlibCompressedRatio(rd) >= 0.88 && hasHighDeltaEntropy(rd) {
					return true
				}
			}
			if isBitAgnosticIncompressibleHighEntropy(residual, true) && hasHighDeltaEntropy(residual) {
				return true
			}
		}
	}
	return false
}

func hasRandomLowLanePlusDelta(b []byte, stride, lowOff int) bool {
	if stride <= 0 || len(b) < stride*minEntropyBytes {
		return false
	}
	cnt := len(b) / stride
	lowLane := make([]byte, cnt)
	for i := 0; i < cnt; i++ {
		lowLane[i] = b[i*stride+lowOff]
	}
	if isBitAgnosticIncompressibleHighEntropy(lowLane, true) && hasHighDeltaEntropy(lowLane) {
		return true
	}
	if _, highEnt := checkHighEntropy(lowLane); !highEnt || zlibCompressedRatio(lowLane) < 0.88 {
		return false
	}
	deltaLow := make([]byte, cnt-1)
	for i := 1; i < cnt; i++ {
		deltaLow[i-1] = lowLane[i] - lowLane[i-1]
	}
	if _, dHigh := checkHighEntropy(deltaLow); dHigh && zlibCompressedRatio(deltaLow) >= 0.85 {
		return true
	}
	return false
}

func isMonotonicOrSmoothNumericTable(b []byte) bool {
	if len(b) < minEntropyBytes {
		return false
	}
	constLaneHighEnt := hasConstantLanePlusHighEntResidual(b)
	if len(b)%2 == 0 {
		cnt := len(b) / 2
		deltaBytes := make([]byte, (cnt-1)*2)
		for _, bigEnd := range []bool{false, true} {
			read16 := func(i int) int {
				if bigEnd {
					return int(binary.BigEndian.Uint16(b[i*2 : i*2+2]))
				}
				return int(binary.LittleEndian.Uint16(b[i*2 : i*2+2]))
			}
			nonDec, nonInc := 0, 0
			var sumDiff, sumDDiff uint64
			prev := read16(0)
			prevDelta := 0
			for i := 1; i < cnt; i++ {
				cur := read16(i)
				if cur < prev {
					nonDec++
				}
				if cur > prev {
					nonInc++
				}
				rawDelta := cur - prev
				binary.LittleEndian.PutUint16(deltaBytes[(i-1)*2:(i-1)*2+2], uint16(rawDelta))
				d := rawDelta
				if d < 0 {
					d = -d
				}
				sumDiff += uint64(d)
				if i >= 2 {
					dd := rawDelta - prevDelta
					if dd < 0 {
						dd = -dd
					}
					sumDDiff += uint64(dd)
				}
				prevDelta = rawDelta
				prev = cur
			}
			lowOff := 0
			if bigEnd {
				lowOff = 1
			}
			if min(nonDec, nonInc) <= max(2, cnt/16) && zlibCompressedRatio(deltaBytes) < 0.70 && !hasRandomLowLanePlusDelta(b, 2, lowOff) {
				return true
			}
			avgDiff := sumDiff / uint64(cnt-1)
			avgDDiff := uint64(0)
			if cnt > 2 {
				avgDDiff = sumDDiff / uint64(cnt-2)
			}
			if !constLaneHighEnt && avgDiff < 1024 && (avgDDiff*2 <= avgDiff+8 || zlibCompressedRatio(deltaBytes) < 0.80) {
				return true
			}
		}
	}
	if len(b)%4 == 0 && len(b) >= 256 {
		cnt := len(b) / 4
		deltaBytes := make([]byte, (cnt-1)*4)
		for _, bigEnd := range []bool{false, true} {
			read32 := func(i int) int64 {
				if bigEnd {
					return int64(binary.BigEndian.Uint32(b[i*4 : i*4+4]))
				}
				return int64(binary.LittleEndian.Uint32(b[i*4 : i*4+4]))
			}
			nonDec, nonInc := 0, 0
			var sumDiff, sumDDiff uint64
			prev := read32(0)
			var prevDelta int64
			for i := 1; i < cnt; i++ {
				cur := read32(i)
				if cur < prev {
					nonDec++
				}
				if cur > prev {
					nonInc++
				}
				rawDelta := cur - prev
				binary.LittleEndian.PutUint32(deltaBytes[(i-1)*4:(i-1)*4+4], uint32(rawDelta))
				d := rawDelta
				if d < 0 {
					d = -d
				}
				sumDiff += uint64(d)
				if i >= 2 {
					dd := rawDelta - prevDelta
					if dd < 0 {
						dd = -dd
					}
					sumDDiff += uint64(dd)
				}
				prevDelta = rawDelta
				prev = cur
			}
			lowOff := 0
			if bigEnd {
				lowOff = 3
			}
			if min(nonDec, nonInc) <= max(2, cnt/16) && zlibCompressedRatio(deltaBytes) < 0.70 && !hasRandomLowLanePlusDelta(b, 4, lowOff) {
				return true
			}
			avgDiff := sumDiff / uint64(cnt-1)
			avgDDiff := uint64(0)
			if cnt > 2 {
				avgDDiff = sumDDiff / uint64(cnt-2)
			}
			if !constLaneHighEnt && avgDiff < 65536 && (avgDDiff*2 <= avgDiff+64 || zlibCompressedRatio(deltaBytes) < 0.70) {
				return true
			}
		}
	}
	if len(b) >= 256 {
		trail := len(b) % 8
		alignedLen := len(b) - trail
		allZeroTrail := true
		for k := alignedLen; k < len(b); k++ {
			if b[k] != 0 {
				allZeroTrail = false
				break
			}
		}
		if allZeroTrail && alignedLen >= 256 {
			cnt := alignedLen / 8
			deltaBytes := make([]byte, (cnt-1)*8)
			for _, bigEnd := range []bool{false, true} {
				read64 := func(i int) uint64 {
					if bigEnd {
						return binary.BigEndian.Uint64(b[i*8 : i*8+8])
					}
					return binary.LittleEndian.Uint64(b[i*8 : i*8+8])
				}
				nonDec, nonInc := 0, 0
				prev := read64(0)
				for i := 1; i < cnt; i++ {
					cur := read64(i)
					if cur < prev {
						nonDec++
					}
					if cur > prev {
						nonInc++
					}
					binary.LittleEndian.PutUint64(deltaBytes[(i-1)*8:(i-1)*8+8], cur-prev)
					prev = cur
				}
				lowOff := 0
				if bigEnd {
					lowOff = 7
				}
				if min(nonDec, nonInc) <= max(2, cnt/16) && zlibCompressedRatio(deltaBytes) < 0.70 && !hasRandomLowLanePlusDelta(b[:alignedLen], 8, lowOff) {
					return true
				}
			}
		}
	}
	return false
}

func isStructuredLookupTable(rem, stripped []byte, strippedHighEnt bool) bool {
	if isMonotonicOrSmoothNumericTable(rem) {
		return true
	}
	if hasConstantLanePlusHighEntResidual(rem) {
		return false
	}
	pCol := collapseRepeatedPeriodic(rem, 32, 4)
	if len(pCol) >= minEntropyBytes && len(pCol) < len(rem)*9/10 {
		if _, pHigh := checkHighEntropyThresh(pCol, 7.70); pHigh && zlibCompressedRatio(pCol) >= 0.90 {
			return false
		}
	}
	hasCSPRNGSubWindow := func(buf []byte) bool {
		if len(buf) < 512 {
			return false
		}
		for off := 0; off < len(buf); off += 256 {
			end := min(len(buf), off+512)
			if len(buf)-end < minEntropyBytes {
				end = len(buf)
			}
			blk := buf[off:end]
			if _, blkHighEnt := checkHighEntropyThresh(blk, 7.80); blkHighEnt && zlibCompressedRatio(blk) >= 0.92 && !isMonotonicOrSmoothNumericTable(blk) {
				return true
			}
			if end == len(buf) {
				break
			}
		}
		return false
	}
	if zlibCompressedRatio(rem) < 0.80 && !hasCSPRNGSubWindow(rem) {
		return true
	}
	if strippedHighEnt && len(stripped) >= minEntropyBytes && zlibCompressedRatio(stripped) >= 0.85 {
		return false
	}
	collapsed := collapseRepeatedBytes(rem, 16)
	if len(collapsed) < minEntropyBytes {
		return true
	}
	if _, highEnt := checkHighEntropy(collapsed); !highEnt {
		cStripped := stripControlBytesForInspection(collapsed)
		if len(cStripped) < minEntropyBytes || len(cStripped) >= len(collapsed)*9/10 {
			return true
		}
		if _, sh := checkHighEntropy(cStripped); !sh {
			return true
		}
	}
	if zlibCompressedRatio(collapsed) < 0.85 && !hasCSPRNGSubWindow(collapsed) {
		return true
	}
	return false
}

func isExemptWASMDataSegment(seg []byte) ([]byte, bool) {
	return isExemptWASMDataSegmentOpt(seg, true)
}

func isExemptWASMDataSegmentOpt(seg []byte, allowTopK bool) ([]byte, bool) {
	rem := removeCRC32Tables(seg)
	if len(rem) < minEntropyBytes {
		return rem, true
	}
	_, rawHighEnt := checkHighEntropy(rem)
	stripped := stripControlBytesForInspection(rem)
	strippedHighEnt := false
	if len(stripped) >= minEntropyBytes && len(stripped) < len(rem)*9/10 {
		_, strippedHighEnt = checkHighEntropy(stripped)
	}
	collapsed := collapseRepeatedBytes(rem, 16)
	collapsedHighEnt := false
	if len(collapsed) >= minEntropyBytes && len(collapsed) < len(rem)*9/10 {
		_, collapsedHighEnt = checkHighEntropy(collapsed)
	}
	pCollapsed := collapseRepeatedPeriodic(rem, 32, 4)
	if len(pCollapsed) >= minEntropyBytes && len(pCollapsed) < len(rem)*9/10 {
		if _, pHigh := checkHighEntropy(pCollapsed); pHigh {
			collapsedHighEnt = true
		}
	}
	constLaneHighEnt := hasConstantLanePlusHighEntResidual(rem)
	domHighEnt := false
	dom, domOK := stripDominantByteIfOver(rem, 15)
	if domOK && len(dom) >= minEntropyBytes && checkMaxEntWindowIncompressible(dom, entropyThreshold) {
		domHighEnt = true
	}
	bitHighEnt := isBitAgnosticIncompressibleHighEntropy(rem, true) ||
		(len(collapsed) >= minEntropyBytes && len(collapsed) < len(rem)*9/10 && isBitAgnosticIncompressibleHighEntropy(collapsed, true)) ||
		(len(pCollapsed) >= minEntropyBytes && len(pCollapsed) < len(rem)*9/10 && isBitAgnosticIncompressibleHighEntropy(pCollapsed, true))
	topKDiluted := allowTopK && isTopKPadDilutedHighEntropy(rem, true)
	if !rawHighEnt && !strippedHighEnt && !collapsedHighEnt && !constLaneHighEnt && !domHighEnt && !bitHighEnt && !topKDiluted {
		return rem, true
	}
	if !bitHighEnt && isMonotonicOrSmoothNumericTable(rem) {
		return rem, true
	}
	if !bitHighEnt && !topKDiluted && !domHighEnt && !constLaneHighEnt && isStructuredLookupTable(rem, stripped, strippedHighEnt) {
		return rem, true
	}
	return rem, false
}

type wasmDataSegAddr struct {
	addr    int64
	hasAddr bool
	data    []byte
}

func readSLEB128I32(b []byte) (int64, int, bool) {
	var val uint32
	var shift uint
	for i := 0; i < 5 && i < len(b); i++ {
		cur := b[i]
		val |= uint32(cur&0x7f) << shift
		shift += 7
		if cur&0x80 == 0 {
			if shift < 32 && (cur&0x40) != 0 {
				val |= ^uint32(0) << shift
			}
			return int64(int32(val)), i + 1, true
		}
	}
	return 0, 0, false
}

func parseWASMDataSectionWithAddrs(b []byte) ([]wasmDataSegAddr, bool) {
	segCount, off, ok := readULEB128(b)
	if !ok || segCount > 100000 {
		return nil, false
	}
	segs := make([]wasmDataSegAddr, 0, min(int(segCount), 64))
	for i := uint64(0); i < segCount; i++ {
		mode, adv, ok := readULEB128(b[off:])
		if !ok || mode > 2 {
			return nil, false
		}
		off += adv
		if mode == 2 {
			_, madv, ok := readULEB128(b[off:])
			if !ok {
				return nil, false
			}
			off += madv
		}
		var segAddr int64
		hasAddr := false
		if mode == 0 || mode == 2 {
			if mode == 0 && off < len(b) && b[off] == 0x41 {
				if v, sAdv, sOK := readSLEB128I32(b[off+1:]); sOK && off+1+sAdv < len(b) && b[off+1+sAdv] == 0x0b {
					segAddr = v
					hasAddr = true
				}
			}
			eadv, ok := skipWASMInitExpr(b[off:])
			if !ok {
				return nil, false
			}
			off += eadv
		}
		dataLen, dadv, ok := readULEB128(b[off:])
		if !ok {
			return nil, false
		}
		off += dadv
		if dataLen > uint64(len(b)-off) {
			return nil, false
		}
		segs = append(segs, wasmDataSegAddr{addr: segAddr, hasAddr: hasAddr, data: b[off : off+int(dataLen)]})
		off += int(dataLen)
	}
	return segs, off == len(b)
}

func hasValidGoWASMPclntab(segs []wasmDataSegAddr, funcCount10 uint64) bool {
	if funcCount10 < 512 {
		return false
	}
	magics := [][]byte{
		{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00},
		{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00},
	}
	for _, seg := range segs {
		if !seg.hasAddr || len(seg.data) < 6 {
			continue
		}
		for _, magic := range magics {
			searchOff := 0
			for searchOff+6 <= len(seg.data) {
				rel := bytes.Index(seg.data[searchOff:], magic)
				if rel < 0 {
					break
				}
				mOff := searchOff + rel
				searchOff = mOff + 1
				baseAddr := seg.addr + int64(mOff)
				var win [512]byte
				for _, s := range segs {
					if !s.hasAddr || len(s.data) == 0 {
						continue
					}
					sEnd := s.addr + int64(len(s.data))
					if sEnd <= baseAddr || s.addr >= baseAddr+512 {
						continue
					}
					ovStart := max(baseAddr, s.addr)
					ovEnd := min(baseAddr+512, sEnd)
					copy(win[ovStart-baseAddr:ovEnd-baseAddr], s.data[ovStart-s.addr:ovEnd-s.addr])
				}
				if win[4] != 0 || win[5] != 0 {
					continue
				}
				minLC := win[6]
				ptrSize := win[7]
				if (minLC != 1 && minLC != 2 && minLC != 4) || (ptrSize != 4 && ptrSize != 8) {
					continue
				}
				var nfunc, nfiles, fnOff, cuOff, ftOff, pcOff, pclnOff uint64
				var hdrSz uint64
				if ptrSize == 8 {
					nfunc = binary.LittleEndian.Uint64(win[8:16])
					nfiles = binary.LittleEndian.Uint64(win[16:24])
					fnOff = binary.LittleEndian.Uint64(win[32:40])
					cuOff = binary.LittleEndian.Uint64(win[40:48])
					ftOff = binary.LittleEndian.Uint64(win[48:56])
					pcOff = binary.LittleEndian.Uint64(win[56:64])
					pclnOff = binary.LittleEndian.Uint64(win[64:72])
					hdrSz = 72
				} else {
					nfunc = uint64(binary.LittleEndian.Uint32(win[8:12]))
					nfiles = uint64(binary.LittleEndian.Uint32(win[12:16]))
					fnOff = uint64(binary.LittleEndian.Uint32(win[20:24]))
					cuOff = uint64(binary.LittleEndian.Uint32(win[24:28]))
					ftOff = uint64(binary.LittleEndian.Uint32(win[28:32]))
					pcOff = uint64(binary.LittleEndian.Uint32(win[32:36]))
					pclnOff = uint64(binary.LittleEndian.Uint32(win[36:40]))
					hdrSz = 40
				}
				if nfunc < 512 || nfunc > funcCount10*2 || funcCount10 > nfunc*2 || nfiles < 1 {
					continue
				}
				if fnOff != hdrSz || fnOff >= cuOff || cuOff >= ftOff || ftOff >= pcOff || pcOff >= pclnOff {
					continue
				}
				endTab := min(512, int(cuOff))
				if endTab-int(hdrSz) < 64 {
					continue
				}
				tab := win[hdrSz:endTab]
				okBytes := 0
				printBytes := 0
				for _, x := range tab {
					if x == 0 || (x >= 0x20 && x <= 0x7e) {
						okBytes++
					}
					if x >= 0x21 && x <= 0x7e {
						printBytes++
					}
				}
				if okBytes*10 >= len(tab)*9 && printBytes >= 16 {
					return true
				}
			}
		}
	}
	return false
}

func inspectWASMCustomSections(
	ctx context.Context,
	virtualPath string,
	data []byte,
	archiveDepth int,
	decodeDepth int,
	inArchive bool,
	inEncoded bool,
	budget *archiveBudget,
	decodeRemaining *int64,
	res *l4FileResult,
) {
	if len(data) <= 8 {
		return
	}

	// Pass 1: Determine whether module has substantial compiled code (matching secID 1, 3, and 10, plus secID 11 ratio).
	var hasType1, hasFunc3, hasCode10, codeSubstantial bool
	var funcCount3, funcCount10 uint64
	var totalCodeBytes, totalSec11Bytes int
	var allDataSegs []wasmDataSegAddr
	sec10Info := make(map[int]struct {
		codeOK    bool
		concealed bool
	})
	for off := 8; off < len(data); {
		secStart := off
		secID := data[off]
		off++
		secLen, adv, ok := readULEB128(data[off:])
		if !ok {
			break
		}
		off += adv
		if secLen > uint64(len(data)-off) {
			break
		}
		secBody := data[off : off+int(secLen)]
		switch secID {
		case 1:
			if parseWASMTypeSection(secBody) {
				hasType1 = true
			}
		case 3:
			if cnt, fok := parseWASMFunctionSection(secBody); fok {
				hasFunc3 = true
				funcCount3 = cnt
			}
		case 10:
			cnt, codeBytes, subst, conc, cok := parseWASMCodeSectionWithConceal(secBody, true)
			sec10Info[secStart] = struct {
				codeOK    bool
				concealed bool
			}{codeOK: cok, concealed: conc}
			if cok {
				hasCode10 = true
				funcCount10 = cnt
				totalCodeBytes += codeBytes
				codeSubstantial = subst
			}
		case 11:
			totalSec11Bytes += len(secBody)
			if segsWithAddrs, dok := parseWASMDataSectionWithAddrs(secBody); dok {
				allDataSegs = append(allDataSegs, segsWithAddrs...)
			}
		}
		off += int(secLen)
	}
	hasSubstantialCode := hasType1 && hasFunc3 && hasCode10 && funcCount3 == funcCount10 && codeSubstantial && totalSec11Bytes <= totalCodeBytes
	hasGoRuntime := hasSubstantialCode && funcCount10 >= 512 && totalCodeBytes >= 512*1024 && hasValidGoWASMPclntab(allDataSegs, funcCount10)

	var aggEntropyRaw bytes.Buffer
	var aggEntropyStripped bytes.Buffer
	var aggPrintable bytes.Buffer
	emittedEntropy := false

	appendBounded := func(buf *bytes.Buffer, b []byte) {
		if buf.Len() >= maxDecodedTotalPerFile || len(b) == 0 {
			return
		}
		rem := maxDecodedTotalPerFile - buf.Len()
		if len(b) > rem {
			buf.Write(b[:rem])
		} else {
			buf.Write(b)
		}
	}

	emitWASMEntropy := func(secLabel, kind string, ent float64, size int) {
		emittedEntropy = true
		msg := fmt.Sprintf("high-entropy payload inside WASM %s section", secLabel)
		if kind == "stripped" {
			msg = fmt.Sprintf("high-entropy C0-diluted payload inside WASM %s section", secLabel)
		}
		res.Findings = append(res.Findings, makeConcealmentFinding(
			"ip.l4.high-entropy",
			domain.SeverityHigh,
			virtualPath,
			msg,
			map[string]any{
				"layer":         "L4_CONCEALMENT",
				"technique":     "high_entropy",
				"wasm_section":  secLabel,
				"shannon_bits":  math.Round(ent*1000) / 1000,
				"payload_bytes": size,
			},
			fmt.Sprintf("wasm_%s_%s_entropy:%.3f:%d", secLabel, kind, ent, size),
		))
	}

	inspectPayloadSection := func(secLabel string, payload []byte, printablePayload []byte, checkRawEntropy, checkStrippedEntropy, aggRaw, aggStripped, rawPrintable bool) {
		stripped := stripControlBytesForInspection(payload)
		if checkRawEntropy {
			if ent, flagged := checkHighEntropy(payload); flagged {
				emitWASMEntropy(secLabel, "raw", ent, len(payload))
			}
			if aggRaw {
				appendBounded(&aggEntropyRaw, payload)
			}
		}
		if checkStrippedEntropy {
			if len(stripped) >= minEntropyBytes && len(stripped) < len(payload)*9/10 {
				if ent, flagged := checkHighEntropy(stripped); flagged {
					emitWASMEntropy(secLabel, "stripped", ent, len(stripped))
				}
			}
			if aggStripped {
				appendBounded(&aggEntropyStripped, stripped)
			}
		}
		emitCredentialFindings(virtualPath, payload, res)
		if len(stripped) > 0 && len(stripped) != len(payload) {
			emitCredentialFindings(virtualPath, stripped, res)
		}
		printStripped := stripControlBytesForInspection(printablePayload)
		if len(printStripped) > 0 {
			emitCredentialFindings(virtualPath, printStripped, res)
			if rawPrintable {
				if secLabel != "custom" && aggPrintable.Len() > 0 {
					aggPrintable.WriteByte('\n')
				}
				appendBounded(&aggPrintable, printStripped)
			} else if runs := extractPrintableTextRuns(printStripped, 32); len(runs) > 0 {
				if aggPrintable.Len() > 0 {
					aggPrintable.WriteByte('\n')
				}
				appendBounded(&aggPrintable, runs)
			}
		}
	}

	off := 8
	for off < len(data) {
		secStart := off
		secID := data[off]
		off++
		secLen, adv, ok := readULEB128(data[off:])
		if !ok {
			break
		}
		off += adv
		if secLen > uint64(len(data)-off) {
			break
		}
		secBody := data[off : off+int(secLen)]
		switch {
		case secID == 0:
			nameLen, nameAdv, nameOK := readULEB128(secBody)
			if nameOK && nameLen <= secLen-uint64(nameAdv) {
				payload := secBody[nameAdv+int(nameLen):]
				inspectPayloadSection("custom", payload, payload, true, true, true, true, true)
			}
		case secID == 9:
			_, rawHighEnt := checkHighEntropy(secBody)
			// Valid substantial WASM Elem (secID==9) tables contain 2-byte LEB128 function indices with 0x00..0x1f high bytes.
			if hasSubstantialCode && !rawHighEnt {
				inspectPayloadSection("sec_9", secBody, secBody, true, false, false, false, false)
			} else {
				inspectPayloadSection("sec_9", secBody, secBody, true, true, true, true, false)
			}
		case secID == 10:
			info := sec10Info[secStart]
			// Do not C0-strip valid non-concealed WASM Code (secID==10) VM opcodes (0x00..0x1f).
			if info.codeOK && !info.concealed {
				inspectPayloadSection("sec_10", secBody, secBody, true, false, !hasSubstantialCode, false, false)
			} else {
				beforeEmitted := emittedEntropy
				inspectPayloadSection("sec_10", secBody, secBody, true, true, true, true, false)
				if info.concealed && emittedEntropy == beforeEmitted {
					emitWASMEntropy("sec_10", "concealed", 7.2, len(secBody))
				}
			}
		case secID == 11:
			segs, dataOK := parseWASMDataSection(secBody)
			printableBuf := secBody
			if dataOK && len(segs) > 0 {
				var joined bytes.Buffer
				for i, s := range segs {
					if i > 0 {
						joined.WriteByte('\n')
					}
					joined.Write(s)
				}
				printableBuf = joined.Bytes()
			}
			if !dataOK {
				inspectPayloadSection("data", secBody, printableBuf, true, true, true, true, true)
			} else {
				inspectPayloadSection("data", secBody, printableBuf, false, false, false, false, true)
				var smallSegs, smallStripped, smallCollapsed bytes.Buffer
				unexemptBytes := 0
				hasIncompressibleHighEntUnexempt := false
				emitUnexempt := func(rem []byte, sizeForRatio int) {
					unexemptBytes += sizeForRatio
					if hasGoRuntime {
						if _, rawH := checkHighEntropy(rem); rawH {
							hasIncompressibleHighEntUnexempt = true
							return
						}
						if isBitAgnosticIncompressibleHighEntropy(rem, true) {
							hasIncompressibleHighEntUnexempt = true
							return
						}
						if isTopKPadDilutedHighEntropy(rem, true) {
							hasIncompressibleHighEntUnexempt = true
							return
						}
						if col := collapseRepeatedBytes(rem, 16); len(col) >= minEntropyBytes && len(col) < len(rem)*9/10 {
							if _, h := checkHighEntropy(col); h || isBitAgnosticIncompressibleHighEntropy(col, true) {
								hasIncompressibleHighEntUnexempt = true
								return
							}
						}
						if pCol := collapseRepeatedPeriodic(rem, 32, 4); len(pCol) >= minEntropyBytes && len(pCol) < len(rem)*9/10 {
							if checkMaxEntWindowIncompressible(pCol, entropyThreshold) || isBitAgnosticIncompressibleHighEntropy(pCol, true) {
								hasIncompressibleHighEntUnexempt = true
								return
							}
						}
						if hasConstantLanePlusHighEntResidual(rem) {
							hasIncompressibleHighEntUnexempt = true
							return
						}
						if dom, ok := stripDominantByteIfOver(rem, 15); ok && len(dom) >= minEntropyBytes {
							if checkMaxEntWindowIncompressible(dom, entropyThreshold) {
								hasIncompressibleHighEntUnexempt = true
								return
							}
						}
						if st := stripControlBytesForInspection(rem); len(st) >= minEntropyBytes && len(st) < len(rem)*9/10 {
							if _, h := checkHighEntropyThresh(st, 7.60); h {
								hasIncompressibleHighEntUnexempt = true
								return
							}
						}
						return
					}
					if ent, flagged := checkHighEntropy(rem); flagged {
						emitWASMEntropy("data", "raw", ent, len(rem))
					} else {
						strippedRem := stripControlBytesForInspection(rem)
						if ent, sFlagged := checkHighEntropy(strippedRem); sFlagged {
							emitWASMEntropy("data", "stripped", ent, len(strippedRem))
						} else {
							emitWASMEntropy("data", "raw", 7.2, len(rem))
						}
					}
				}
				for _, seg := range segs {
					if len(seg) < minEntropyBytes {
						appendBounded(&smallSegs, seg)
						continue
					}
					rem, exempt := isExemptWASMDataSegment(seg)
					if !exempt {
						emitUnexempt(rem, len(rem))
						continue
					}
					if isMonotonicOrSmoothNumericTable(rem) {
						continue
					}
					st := stripControlBytesForInspection(rem)
					if len(st) > 0 && len(st) < minEntropyBytes && len(st) < len(rem)*9/10 {
						appendBounded(&smallStripped, st)
					} else {
						col := collapseRepeatedPeriodic(rem, 32, 4)
						if len(col) > 0 && len(col) < minEntropyBytes && len(col) < len(rem)*9/10 {
							appendBounded(&smallCollapsed, col)
						}
					}
				}
				checkSmallBuf := func(buf *bytes.Buffer, allowTopK bool) bool {
					if buf.Len() < minEntropyBytes {
						return false
					}
					rem, exempt := isExemptWASMDataSegmentOpt(buf.Bytes(), allowTopK)
					if !exempt {
						emitUnexempt(rem, buf.Len())
						return true
					}
					return true
				}
				checkedSegs := checkSmallBuf(&smallSegs, true)
				checkedStripped := checkSmallBuf(&smallStripped, false)
				checkedCollapsed := checkSmallBuf(&smallCollapsed, false)
				if !hasGoRuntime {
					var mixedSmall bytes.Buffer
					if !checkedSegs && smallSegs.Len() > 0 {
						appendBounded(&mixedSmall, smallSegs.Bytes())
					}
					if !checkedStripped && smallStripped.Len() > 0 {
						appendBounded(&mixedSmall, smallStripped.Bytes())
					}
					if !checkedCollapsed && smallCollapsed.Len() > 0 {
						appendBounded(&mixedSmall, smallCollapsed.Bytes())
					}
					if mixedSmall.Len() >= minEntropyBytes {
						if rem, exempt := isExemptWASMDataSegment(mixedSmall.Bytes()); !exempt {
							emitUnexempt(rem, mixedSmall.Len())
						}
					} else if mixedSmall.Len() > 0 {
						mb := mixedSmall.Bytes()
						appendBounded(&aggEntropyRaw, mb)
						appendBounded(&aggEntropyStripped, stripControlBytesForInspection(mb))
					}
				} else if hasIncompressibleHighEntUnexempt || unexemptBytes > 8192 {
					emitWASMEntropy("data", "raw", 7.7, max(unexemptBytes, minEntropyBytes))
				}
			}
		case secID >= 1 && secID <= 12:
			inspectPayloadSection(fmt.Sprintf("sec_%d", secID), secBody, secBody, true, true, true, true, false)
		}
		off += int(secLen)
	}

	if !emittedEntropy && aggEntropyRaw.Len() >= minEntropyBytes {
		if ent, flagged := checkHighEntropy(aggEntropyRaw.Bytes()); flagged {
			emittedEntropy = true
			res.Findings = append(res.Findings, makeConcealmentFinding(
				"ip.l4.high-entropy",
				domain.SeverityHigh,
				virtualPath,
				"high-entropy aggregated payload across WASM sections",
				map[string]any{
					"layer":         "L4_CONCEALMENT",
					"technique":     "high_entropy",
					"wasm_section":  "aggregated",
					"shannon_bits":  math.Round(ent*1000) / 1000,
					"payload_bytes": aggEntropyRaw.Len(),
				},
				fmt.Sprintf("wasm_agg_entropy:%.3f:%d", ent, aggEntropyRaw.Len()),
			))
		} else if aggEntropyStripped.Len() >= minEntropyBytes && aggEntropyStripped.Len() < aggEntropyRaw.Len()*9/10 {
			if ent, flagged := checkHighEntropy(aggEntropyStripped.Bytes()); flagged {
				emittedEntropy = true
				res.Findings = append(res.Findings, makeConcealmentFinding(
					"ip.l4.high-entropy",
					domain.SeverityHigh,
					virtualPath,
					"high-entropy C0-diluted aggregated payload across WASM sections",
					map[string]any{
						"layer":         "L4_CONCEALMENT",
						"technique":     "high_entropy",
						"wasm_section":  "aggregated",
						"shannon_bits":  math.Round(ent*1000) / 1000,
						"payload_bytes": aggEntropyStripped.Len(),
					},
					fmt.Sprintf("wasm_agg_stripped_entropy:%.3f:%d", ent, aggEntropyStripped.Len()),
				))
			}
		}
	}

	if extracted := extractPrintableTextRuns(aggPrintable.Bytes(), 32); len(extracted) > 0 {
		subPath := virtualPath + "#wasm_sections"
		res.InspectBuffers = append(res.InspectBuffers, inspectedBuffer{
			VirtualPath:    subPath,
			Data:           extracted,
			InArchive:      inArchive,
			InEncoded:      inEncoded,
			ExtractedMedia: true,
		})
		emitCredentialFindings(subPath, extracted, res)
		if decodeDepth < maxDecodeRecursionDepth && *decodeRemaining > 0 {
			inspectEncodedPayloads(ctx, subPath, extracted, archiveDepth, decodeDepth, inArchive, budget, decodeRemaining, res)
		}
	}
}

func readULEB128(b []byte) (uint64, int, bool) {
	var val uint64
	var shift uint
	for i := 0; i < 5 && i < len(b); i++ {
		cur := b[i]
		if i == 4 && (cur&0xf0) != 0 {
			return 0, 0, false
		}
		val |= uint64(cur&0x7f) << shift
		if cur&0x80 == 0 {
			return val, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}
