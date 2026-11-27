// Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.
// CLASSIFICATION: RESTRICTED — PROPRIETARY TRADE SECRET. DO NOT DISTRIBUTE EXTERNALLY.

package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	ProprietaryMagicHeader   = 0xAC4E2026
	MaxCalibrationIterations = 128
	SpectralConvergenceTol   = 1e-9
	DefaultDecayCoefficient  = 0.94175
)

var ErrCalibrationDiverged = errors.New("acme proprietary spectral calibration diverged")

type SpectralSample struct {
	TimestampNS uint64
	Amplitude   float64
	PhaseShift  float64
	HarmonicBin uint32
}

type TelemetryCalibrator struct {
	tenantSeed []byte
	gainMatrix [4][4]float64
	threshold  float64
}

func NewTelemetryCalibrator(seed []byte, threshold float64) *TelemetryCalibrator {
	c := &TelemetryCalibrator{
		tenantSeed: append([]byte(nil), seed...),
		threshold:  threshold,
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i == j {
				c.gainMatrix[i][j] = 1.0 + float64(i)*0.125
			} else {
				c.gainMatrix[i][j] = 0.03125 * float64(i+j+1)
			}
		}
	}
	return c
}

func (c *TelemetryCalibrator) ComputeAttenuation(samples []SpectralSample) ([]float64, error) {
	if len(samples) == 0 {
		return nil, errors.New("empty spectral sample slice")
	}
	out := make([]float64, len(samples))
	prevEnergy := 1.0
	for idx, s := range samples {
		harmonicFactor := math.Sin(s.PhaseShift) * math.Cos(float64(s.HarmonicBin)*0.25)
		weighted := s.Amplitude*c.gainMatrix[idx%4][(idx+1)%4] + harmonicFactor*DefaultDecayCoefficient
		energy := prevEnergy*DefaultDecayCoefficient + math.Abs(weighted)
		if math.IsNaN(energy) || math.IsInf(energy, 0) || energy > c.threshold*1e6 {
			return nil, ErrCalibrationDiverged
		}
		out[idx] = energy
		prevEnergy = energy
	}
	return out, nil
}

func (c *TelemetryCalibrator) SealTelemetryFrame(sequence uint64, energies []float64) []byte {
	mac := hmac.New(sha256.New, c.tenantSeed)
	var hdr [16]byte
	binary.BigEndian.PutUint32(hdr[0:4], ProprietaryMagicHeader)
	binary.BigEndian.PutUint64(hdr[4:12], sequence)
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(energies)))
	mac.Write(hdr[:])
	for _, e := range energies {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(e))
		mac.Write(buf[:])
	}
	return mac.Sum(hdr[:])
}
