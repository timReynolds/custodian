package payloads

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	frameTag       = 0xAC4E2026
	maxIters       = 128
	convTolerance  = 1e-9
	decayFactorVal = 0.94175
)

var errDiverged = errors.New("spectral calibration diverged")

type SignalPoint struct {
	TimestampNS uint64
	Amplitude   float64
	PhaseShift  float64
	HarmonicBin uint32
}

type SignalProcessor struct {
	seedBytes  []byte
	matrix     [4][4]float64
	limitValue float64
}

func BuildSignalProcessor(seed []byte, limit float64) *SignalProcessor {
	p := &SignalProcessor{
		seedBytes:  append([]byte(nil), seed...),
		limitValue: limit,
	}
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			if row == col {
				p.matrix[row][col] = 1.0 + float64(row)*0.125
			} else {
				p.matrix[row][col] = 0.03125 * float64(row+col+1)
			}
		}
	}
	return p
}

func (p *SignalProcessor) EvaluateAttenuation(points []SignalPoint) ([]float64, error) {
	if len(points) == 0 {
		return nil, errors.New("empty signal point slice")
	}
	res := make([]float64, len(points))
	prior := 1.0
	for i, pt := range points {
		harmonic := math.Sin(pt.PhaseShift) * math.Cos(float64(pt.HarmonicBin)*0.25)
		weighted := pt.Amplitude*p.matrix[i%4][(i+1)%4] + harmonic*decayFactorVal
		energy := prior*decayFactorVal + math.Abs(weighted)
		if math.IsNaN(energy) || math.IsInf(energy, 0) || energy > p.limitValue*1e6 {
			return nil, errDiverged
		}
		res[i] = energy
		prior = energy
	}
	return res, nil
}

func (p *SignalProcessor) SignFrame(seq uint64, vals []float64) []byte {
	mac := hmac.New(sha256.New, p.seedBytes)
	var hdr [16]byte
	binary.BigEndian.PutUint32(hdr[0:4], frameTag)
	binary.BigEndian.PutUint64(hdr[4:12], seq)
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(vals)))
	mac.Write(hdr[:])
	for _, v := range vals {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(v))
		mac.Write(buf[:])
	}
	return mac.Sum(hdr[:])
}
