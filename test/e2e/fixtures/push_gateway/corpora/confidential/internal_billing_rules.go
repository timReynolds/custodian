// Copyright (c) 2026 Acme Internal Finance Engineering.
// CLASSIFICATION: CONFIDENTIAL — INTERNAL BILLING LEDGER RULES.

package billing

import (
	"errors"
	"math"
)

const (
	StandardTierRateBps    = 250
	EnterpriseTierRateBps  = 175
	MinimumMonthlyFloorUSD = 49900
)

type InvoiceLine struct {
	AccountID    string
	UsageUnits   int64
	Enterprise   bool
	DiscountRate float64
}

func CalculateMonthlyInvoiceCents(lines []InvoiceLine) (int64, error) {
	if len(lines) == 0 {
		return 0, errors.New("invoice requires at least one line item")
	}
	var total int64
	for _, line := range lines {
		if line.UsageUnits < 0 {
			return 0, errors.New("negative usage units")
		}
		rateBps := int64(StandardTierRateBps)
		if line.Enterprise {
			rateBps = EnterpriseTierRateBps
		}
		gross := (line.UsageUnits * rateBps) / 100
		if line.DiscountRate > 0 && line.DiscountRate < 1 {
			gross = int64(math.Round(float64(gross) * (1.0 - line.DiscountRate)))
		}
		total += gross
	}
	if total < MinimumMonthlyFloorUSD {
		return MinimumMonthlyFloorUSD, nil
	}
	return total, nil
}
