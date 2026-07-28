# Retained multilingual benchmark

Generated: 2026-07-28T19:57:59.339Z
Previous model: local-logreg-3054e63c1d9f99ec
Current model: local-logreg-07c7960d472167ac

| Language | N | Previous F1 | Current F1 | Change | Current precision | Current recall |
|---|---:|---:|---:|---:|---:|---:|
| English | 800 | 90.7% | 94.7% | +4.0 pp | 100.0% | 90.0% |
| German | 800 | 96.1% | 97.6% | +1.5 pp | 100.0% | 95.3% |
| French | 800 | 92.2% | 93.5% | +1.3 pp | 100.0% | 87.8% |
| Dutch | 800 | 97.0% | 98.5% | +1.4 pp | 100.0% | 97.0% |
| Spanish | 800 | 94.0% | 95.3% | +1.4 pp | 93.5% | 97.3% |
| BHS | 22 | 70.6% | 84.2% | +13.6 pp | 100.0% | 72.7% |

## Integrity

- Frozen before the multilingual training expansion: 2026-07-27T01:42:49.427Z.
- Positive rows are original-language IMC reports; negative rows are authentic language corpora.
- Complete normalized-template groups are excluded from the current model's training.
- The previous model had already seen IMC positives, so this is a conservative retained comparison, not a newly untouched benchmark.
- Threshold selection used only the large internal validation split, not this benchmark.
- BHS rules were calibrated after the first retained score because only 11 positive messages exist. Its row is a
  transparent development comparison, not independent evidence.
- BHS remains too small for a stable population-level F1 claim.
