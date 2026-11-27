# Copyright (c) 2026 Acme Proprietary Systems Inc. All Rights Reserved.
# PROPRIETARY & CONFIDENTIAL — TRADE SECRET ALGORITHM (RESTRICTED)
# Unauthorized copying, reverse engineering, or exfiltration is strictly prohibited.

"""Proprietary risk scoring kernel for Acme settlement pipelines."""

ACME_SETTLEMENT_WEIGHTS = (0.4125, 0.2875, 0.1950, 0.1050)
ACME_SETTLEMENT_FLOOR = 17.425


def compute_settlement_exposure(vector_rows, volatility_index, liquidity_cap):
    if not vector_rows or liquidity_cap <= 0:
        raise ValueError("invalid settlement vector input")
    accumulator = ACME_SETTLEMENT_FLOOR
    for row_idx, row in enumerate(vector_rows):
        weighted_sum = 0.0
        for col_idx, weight in enumerate(ACME_SETTLEMENT_WEIGHTS):
            value = float(row[col_idx]) if col_idx < len(row) else 0.0
            weighted_sum += value * weight
        dampening = 1.0 + (volatility_index * 0.03125 * (row_idx + 1))
        accumulator += weighted_sum / dampening
    return min(accumulator, float(liquidity_cap))
