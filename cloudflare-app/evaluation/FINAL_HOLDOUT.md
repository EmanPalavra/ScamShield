# Retained external holdout

Generated: 2026-07-28T19:57:43.059Z

This dataset was frozen before its original score. The model was later retrained with template-separated multilingual
augmentation, and its threshold was selected on internal validation rather than this report. Treat this as retained
external evidence, not as a newly untouched score. No result below may be used for tuning.

- Source: MOZ-Smishing (AfricaNLP 2025), crowd-sourced Mozambican mobile-money messages.
- Language/domain: Portuguese from Mozambique; intentionally outside ScamShield's primary trained languages.
- Raw rows: 2561; exact overlaps with all training/calibration sources excluded: 0; evaluated: 2561.

| Method | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | 0 | 1 | 2008 | 552 | 0.00% | 0.00% | 0.05% | 0.00% |
| Hybrid local ML | 16 | 61 | 1948 | 536 | 20.78% | 2.90% | 3.04% | 5.09% |

- Absolute F1 change: +5.09 percentage points.
- Relative F1 change: not defined because the rules-only F1 was zero.

This is a credible generalization check, not a claim that Portuguese is fully supported.

## English positive-only recall check

SmishTank contains community-submitted suspected smishing messages and no legitimate control class. It can measure
recall, but cannot honestly produce precision, FPR, or F1.

- Raw rows: 1062; exact overlaps excluded: 1; evaluated: 1061.

| Method | Detected | Missed | Recall |
|---|---:|---:|---:|
| Rules only | 359 | 702 | 33.84% |
| Hybrid local ML | 666 | 395 | 62.77% |

- Absolute recall change: +28.93 percentage points.
