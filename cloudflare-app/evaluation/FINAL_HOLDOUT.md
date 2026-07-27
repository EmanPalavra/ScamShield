# Final untouched holdout

Generated: 2026-07-27T00:23:28.791Z

The model, threshold, integration policy, and application tests were locked before this dataset was scored.
No result below may be used to retune the model without retiring this dataset as an untouched holdout.

- Source: MOZ-Smishing (AfricaNLP 2025), crowd-sourced Mozambican mobile-money messages.
- Language/domain: Portuguese from Mozambique; intentionally outside ScamShield's primary trained languages.
- Raw rows: 2561; exact overlaps with all training/calibration sources excluded: 0; evaluated: 2561.

| Method | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | 0 | 1 | 2008 | 552 | 0.00% | 0.00% | 0.05% | 0.00% |
| Hybrid local ML | 2 | 10 | 1999 | 550 | 16.67% | 0.36% | 0.50% | 0.71% |

- Absolute F1 change: +0.71 percentage points.
- Relative F1 change: not defined because the rules-only F1 was zero.

This is a credible generalization check, not a claim that Portuguese is fully supported.

## English positive-only recall check

SmishTank contains community-submitted suspected smishing messages and no legitimate control class. It can measure
recall, but cannot honestly produce precision, FPR, or F1.

- Raw rows: 1062; exact overlaps excluded: 1; evaluated: 1061.

| Method | Detected | Missed | Recall |
|---|---:|---:|---:|
| Rules only | 359 | 702 | 33.84% |
| Hybrid local ML | 458 | 603 | 43.17% |

- Absolute recall change: +9.33 percentage points.
