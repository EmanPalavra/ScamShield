# Historical pre-model external holdout

Generated: 2026-07-27T00:00:22.818Z
Frozen: 2026-07-27
Alert threshold: 34

This report predates the local statistical model. Its sources were subsequently used for model training, so the
numbers below are retained for reproducibility and must not be presented as post-model unseen performance. Input files
remain pinned to exact repository commits and verified by SHA-256.

## Primary binary benchmark: novel SmishX rows

Only manually labelled smishing and legitimate messages are used. Generic spam is reported separately and does not
count as either a security success or a false positive.

| N | Scam | Legit | Precision | Recall | FPR | F1 |
|---:|---:|---:|---:|---:|---:|---:|
| 321 | 225 | 96 | 75.64% | 26.22% | 19.79% | 38.94% |

- Recall 95% confidence interval: 20.91%–32.33%.
- FPR 95% confidence interval: 13.05%–28.86%.
- Excluded exact calibration overlaps: 566 of 1200.
- Novel generic-spam alert rate: 9.90% (31/313); excluded from primary F1.

## Independent real-world smishing recall: IMC 2025

This source contains reported smishing positives, not legitimate negatives, so it can measure recall but cannot
honestly measure precision or FPR. The security-focused view excludes rows categorized as generic spam, wrong number,
or unspecified.

- All novel reported messages: 20.89% (7074/33862), 95% CI 20.46%–21.33%.
- Security-focused categories: 21.77% (6911/31746), 95% CI 21.32%–22.23%.
- Excluded exact calibration overlaps: 7 of 33869.

### Security recall by language

| Language | N | Detected | Recall | 95% CI |
|---|---:|---:|---:|---:|
| English | 20386 | 6616 | 32.45% | 31.81%–33.10% |
| Spanish | 4505 | 160 | 3.55% | 3.05%–4.13% |
| Dutch | 1936 | 26 | 1.34% | 0.92%–1.96% |
| French | 1150 | 79 | 6.87% | 5.55%–8.48% |
| German | 797 | 14 | 1.76% | 1.05%–2.93% |
| BHS | 11 | 1 | 9.09% | 1.62%–37.74% |

### Alert rate by source category

| Report category | N | Detected | Alert rate | 95% CI |
|---|---:|---:|---:|---:|
| Unspecified | 81 | 6 | 7.41% | 3.44%–15.23% |
| banking | 15277 | 5568 | 36.45% | 35.69%–37.21% |
| delivery | 3810 | 180 | 4.72% | 4.10%–5.44% |
| government | 3248 | 420 | 12.93% | 11.82%–14.13% |
| hey mum/dad | 263 | 9 | 3.42% | 1.81%–6.37% |
| others | 6922 | 556 | 8.03% | 7.42%–8.70% |
| spam | 1710 | 157 | 9.18% | 7.90%–10.64% |
| telecom | 2226 | 178 | 8.00% | 6.94%–9.20% |
| wrong number | 325 | 0 | 0.00% | 0.00%–1.17% |

## Interpretation

The SmishX result is the primary independent precision/recall/F1 estimate. IMC 2025 is the stronger multilingual
recall stress test because it contains tens of thousands of recent public user reports. Small language groups have
wide confidence intervals and must not be presented as precise per-language performance.
