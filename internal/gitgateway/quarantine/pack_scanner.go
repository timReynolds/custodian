package quarantine

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	packHeaderSize  = 12
	packTrailerSize = 20
	minPackBytes    = packHeaderSize + packTrailerSize

	packObjCommit   = 1
	packObjTree     = 2
	packObjBlob     = 3
	packObjTag      = 4
	packObjOfsDelta = 6
	packObjRefDelta = 7
)

type packScanSummary struct {
	NumObjects         uint32
	TotalInflatedBytes int64
}

type ctxLimitedReader struct {
	ctx      context.Context
	r        io.Reader
	max      int64
	n        int64
	exceeded bool
	limitErr error
}

func (c *ctxLimitedReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, domain.WrapError(domain.ErrUnavailable, "QUARANTINE_ABORTED", "pack stream aborted", err)
	}
	if c.exceeded {
		return 0, c.limitErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	rem := c.max - c.n
	if rem <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			c.exceeded = true
			return 0, c.limitErr
		}
		return 0, err
	}
	if int64(len(p)) > rem {
		p = p[:int(rem)]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func spoolPack(ctx context.Context, r io.Reader, dstPath string, maxPackBytes int64) (total int64, bodySHA1 [20]byte, trailer [20]byte, err error) {
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, bodySHA1, trailer, domain.WrapError(domain.ErrInternal, "QUARANTINE_SPOOL_FAILED", "failed creating quarantine pack spool file", err)
	}
	defer func() {
		_ = f.Close()
	}()

	lr := &ctxLimitedReader{
		ctx:      ctx,
		r:        r,
		max:      maxPackBytes,
		limitErr: domain.Unprocessable("PACK_SIZE_LIMIT_EXCEEDED", fmt.Sprintf("packfile exceeds max_pack_bytes limit of %d bytes", maxPackBytes)),
	}

	h := sha1.New()
	var tail [packTrailerSize]byte
	tailLen := 0
	buf := make([]byte, 32*1024)

	for {
		n, readErr := lr.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, werr := f.Write(chunk); werr != nil {
				return total, bodySHA1, trailer, domain.WrapError(domain.ErrInternal, "QUARANTINE_SPOOL_FAILED", "failed writing quarantine pack spool file", werr)
			}
			total += int64(n)

			// Feed bytes preceding the 20-byte trailer into SHA-1 without retaining full pack in RAM.
			if tailLen+n <= packTrailerSize {
				copy(tail[tailLen:], chunk)
				tailLen += n
			} else if n >= packTrailerSize {
				if tailLen > 0 {
					_, _ = h.Write(tail[:tailLen])
				}
				flushEnd := n - packTrailerSize
				_, _ = h.Write(chunk[:flushEnd])
				copy(tail[:], chunk[flushEnd:])
				tailLen = packTrailerSize
			} else {
				// tailLen + n > 20 and n < 20
				emit := tailLen + n - packTrailerSize
				_, _ = h.Write(tail[:emit])
				copy(tail[:], tail[emit:tailLen])
				copy(tail[tailLen-emit:], chunk)
				tailLen = packTrailerSize
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return total, bodySHA1, trailer, readErr
		}
	}

	if err := f.Sync(); err != nil {
		return total, bodySHA1, trailer, domain.WrapError(domain.ErrInternal, "QUARANTINE_SPOOL_FAILED", "failed syncing quarantine pack spool file", err)
	}

	if total == 0 {
		return 0, bodySHA1, trailer, nil
	}
	if total < minPackBytes {
		return total, bodySHA1, trailer, domain.Unprocessable("MALFORMED_PACK", fmt.Sprintf("packfile too short (%d bytes)", total))
	}

	copy(bodySHA1[:], h.Sum(nil))
	trailer = tail
	if !bytes.Equal(bodySHA1[:], trailer[:]) {
		return total, bodySHA1, trailer, domain.Unprocessable("INVALID_PACK_CHECKSUM", "packfile SHA-1 trailer checksum mismatch")
	}
	return total, bodySHA1, trailer, nil
}

// offsetByteReader implements io.Reader and io.ByteReader over a bufio.Reader while
// tracking exact byte offsets consumed so zlib.NewReader never buffers past entry boundaries.
type offsetByteReader struct {
	br  *bufio.Reader
	off int64
}

func (o *offsetByteReader) Read(p []byte) (int, error) {
	n, err := o.br.Read(p)
	o.off += int64(n)
	return n, err
}

func (o *offsetByteReader) ReadByte() (byte, error) {
	b, err := o.br.ReadByte()
	if err == nil {
		o.off++
	}
	return b, err
}

type countingByteReader struct {
	r     io.Reader
	limit int64
	n     int64
}

func (c *countingByteReader) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, io.EOF
	}
	if int64(len(p)) > c.limit-c.n {
		p = p[:int(c.limit-c.n)]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingByteReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := c.Read(b[:])
	if n == 1 {
		return b[0], nil
	}
	if err == nil {
		err = io.EOF
	}
	return 0, err
}

func scanPackFile(ctx context.Context, packPath string, totalBytes int64, limits Limits) (packScanSummary, error) {
	f, err := os.Open(packPath)
	if err != nil {
		return packScanSummary{}, domain.WrapError(domain.ErrInternal, "QUARANTINE_PACK_OPEN_FAILED", "failed opening spooled packfile", err)
	}
	defer f.Close()

	obr := &offsetByteReader{
		br: bufio.NewReaderSize(f, 32*1024),
	}

	var hdr [packHeaderSize]byte
	if _, err := io.ReadFull(obr, hdr[:]); err != nil {
		return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "failed reading packfile header")
	}
	if string(hdr[0:4]) != "PACK" {
		return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "invalid packfile magic header")
	}
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != 2 {
		return packScanSummary{}, domain.Unprocessable("UNSUPPORTED_PACK_VERSION", fmt.Sprintf("unsupported packfile version %d", version))
	}
	numObjects := binary.BigEndian.Uint32(hdr[8:12])
	if uint64(numObjects) > uint64(limits.MaxObjects) {
		return packScanSummary{}, domain.Unprocessable("OBJECT_COUNT_LIMIT_EXCEEDED", fmt.Sprintf("packfile object count %d exceeds max_objects %d", numObjects, limits.MaxObjects))
	}

	bodyEnd := totalBytes - packTrailerSize
	seenOffsets := make(map[int64]struct{}, numObjects)
	deltaDepth := make(map[int64]int)
	var totalInflated int64

	for i := uint32(0); i < numObjects; i++ {
		if err := ctx.Err(); err != nil {
			return packScanSummary{}, domain.WrapError(domain.ErrUnavailable, "QUARANTINE_ABORTED", "pack scan aborted", err)
		}
		if obr.off >= bodyEnd {
			return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "unexpected EOF before all declared pack objects were read")
		}

		entryOffset := obr.off
		seenOffsets[entryOffset] = struct{}{}

		objType, declaredSize, err := readPackEntryHeader(obr)
		if err != nil {
			return packScanSummary{}, err
		}
		if declaredSize > uint64(limits.MaxInflatedObjectBytes) {
			return packScanSummary{}, domain.Unprocessable(
				"INFLATED_OBJECT_LIMIT_EXCEEDED",
				fmt.Sprintf("pack entry size %d exceeds max_inflated_object_bytes %d", declaredSize, limits.MaxInflatedObjectBytes),
			)
		}

		switch objType {
		case packObjCommit, packObjTree, packObjBlob, packObjTag:
		case packObjOfsDelta:
			negOff, err := readOfsDeltaOffset(obr)
			if err != nil {
				return packScanSummary{}, err
			}
			if negOff == 0 || negOff > uint64(entryOffset-packHeaderSize) {
				return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "invalid OFS_DELTA negative base offset")
			}
			baseOff := entryOffset - int64(negOff)
			if _, ok := seenOffsets[baseOff]; !ok {
				return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "OFS_DELTA references unknown base offset")
			}
			depth := deltaDepth[baseOff] + 1
			if depth > limits.MaxDeltaDepth {
				return packScanSummary{}, domain.Unprocessable("DELTA_DEPTH_LIMIT_EXCEEDED", fmt.Sprintf("OFS_DELTA chain depth %d exceeds max_delta_depth %d", depth, limits.MaxDeltaDepth))
			}
			deltaDepth[entryOffset] = depth
		case packObjRefDelta:
			var baseOID [20]byte
			if _, err := io.ReadFull(obr, baseOID[:]); err != nil {
				return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", "truncated REF_DELTA base OID")
			}
		default:
			return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", fmt.Sprintf("unsupported pack object type %d", objType))
		}

		inflatedBytes, err := scanPackEntryZlib(obr, objType, declaredSize, limits.MaxInflatedObjectBytes)
		if err != nil {
			return packScanSummary{}, err
		}
		if totalInflated > limits.MaxTotalInflatedBytes-inflatedBytes {
			return packScanSummary{}, domain.Unprocessable("TOTAL_INFLATED_LIMIT_EXCEEDED", fmt.Sprintf("aggregate inflated pack size exceeds limit %d", limits.MaxTotalInflatedBytes))
		}
		totalInflated += inflatedBytes
	}

	if obr.off != bodyEnd {
		return packScanSummary{}, domain.Unprocessable("MALFORMED_PACK", fmt.Sprintf("packfile body ended at offset %d, expected %d", obr.off, bodyEnd))
	}
	return packScanSummary{
		NumObjects:         numObjects,
		TotalInflatedBytes: totalInflated,
	}, nil
}

func readPackEntryHeader(r io.ByteReader) (objType int, declaredSize uint64, err error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, 0, domain.Unprocessable("MALFORMED_PACK", "truncated pack object header")
	}
	objType = int((b >> 4) & 0x07)
	declaredSize = uint64(b & 0x0f)
	shift := uint(4)
	bytesRead := 1

	for (b & 0x80) != 0 {
		if bytesRead >= 10 || shift >= 64 {
			return 0, 0, domain.Unprocessable("MALFORMED_PACK", "pack object size header overflow")
		}
		b, err = r.ReadByte()
		if err != nil {
			return 0, 0, domain.Unprocessable("MALFORMED_PACK", "truncated pack object size varint")
		}
		bytesRead++
		if shift == 60 && (b&0x70) != 0 {
			return 0, 0, domain.Unprocessable("MALFORMED_PACK", "pack object size varint exceeds uint64")
		}
		declaredSize |= uint64(b&0x7f) << shift
		shift += 7
	}
	return objType, declaredSize, nil
}

func readOfsDeltaOffset(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, domain.Unprocessable("MALFORMED_PACK", "truncated OFS_DELTA offset")
	}
	off := uint64(b & 0x7f)
	bytesRead := 1
	for (b & 0x80) != 0 {
		if bytesRead >= 10 {
			return 0, domain.Unprocessable("MALFORMED_PACK", "OFS_DELTA offset varint overflow")
		}
		b, err = r.ReadByte()
		if err != nil {
			return 0, domain.Unprocessable("MALFORMED_PACK", "truncated OFS_DELTA offset varint")
		}
		bytesRead++
		if off > (^uint64(0)>>7)-1 {
			return 0, domain.Unprocessable("MALFORMED_PACK", "OFS_DELTA offset arithmetic overflow")
		}
		off = ((off + 1) << 7) | uint64(b&0x7f)
	}
	return off, nil
}

func readLEB128Size(r io.ByteReader) (uint64, error) {
	var val uint64
	var shift uint
	for i := 0; i < 10; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, domain.Unprocessable("MALFORMED_PACK", "truncated delta size header")
		}
		if shift >= 64 {
			return 0, domain.Unprocessable("MALFORMED_PACK", "delta size header overflow")
		}
		if shift == 63 && (b&0x7e) != 0 {
			return 0, domain.Unprocessable("MALFORMED_PACK", "delta size varint exceeds uint64")
		}
		val |= uint64(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return val, nil
		}
		shift += 7
	}
	return 0, domain.Unprocessable("MALFORMED_PACK", "delta size header exceeded maximum varint length")
}

func scanPackEntryZlib(obr *offsetByteReader, objType int, declaredSize uint64, maxInflated int64) (int64, error) {
	zr, err := zlib.NewReader(obr)
	if err != nil {
		return 0, domain.Unprocessable("MALFORMED_PACK", "invalid zlib stream in pack entry")
	}
	defer func() {
		_ = zr.Close()
	}()

	limit := int64(declaredSize)
	if limit < math.MaxInt64 {
		limit++
	}
	clr := &countingByteReader{
		r:     zr,
		limit: limit,
	}

	effectiveSize := int64(declaredSize)
	if objType == packObjOfsDelta || objType == packObjRefDelta {
		baseSize, err := readLEB128Size(clr)
		if err != nil {
			return 0, err
		}
		if baseSize > uint64(maxInflated) {
			return 0, domain.Unprocessable(
				"INFLATED_OBJECT_LIMIT_EXCEEDED",
				fmt.Sprintf("delta base size %d exceeds max_inflated_object_bytes %d", baseSize, maxInflated),
			)
		}
		targetSize, err := readLEB128Size(clr)
		if err != nil {
			return 0, err
		}
		if targetSize > uint64(maxInflated) {
			return 0, domain.Unprocessable(
				"INFLATED_OBJECT_LIMIT_EXCEEDED",
				fmt.Sprintf("delta target size %d exceeds max_inflated_object_bytes %d", targetSize, maxInflated),
			)
		}
		effectiveSize = int64(targetSize)
	}

	if _, err := io.Copy(io.Discard, clr); err != nil {
		return 0, domain.Unprocessable("MALFORMED_PACK", "corrupt zlib payload in pack entry")
	}
	if clr.n > int64(declaredSize) {
		return 0, domain.Unprocessable("INFLATED_OBJECT_LIMIT_EXCEEDED", "zlib stream inflated beyond declared pack entry size")
	}
	if clr.n != int64(declaredSize) {
		return 0, domain.Unprocessable("MALFORMED_PACK", "truncated zlib stream in pack entry")
	}
	if err := zr.Close(); err != nil {
		return 0, domain.Unprocessable("MALFORMED_PACK", "invalid zlib checksum or trailer in pack entry")
	}
	return effectiveSize, nil
}
