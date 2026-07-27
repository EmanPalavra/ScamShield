# Local ML model training

Generated: 2026-07-27T00:15:39.679Z
Model: local-logreg-2f92cbeb79037618

- Algorithm: quantized feature-hashed logistic regression with AdaGrad.
- Features: normalized character 3/4-grams, word unigrams/bigrams, and bounded structural indicators.
- Training/validation: 43159/10806, deterministic 80/20 text-hash split after exact deduplication.
- Training positives/negatives: 19481/23678.
- Label conflicts excluded: 0.
- Model size: 16,384 weight bytes before Base64.
- Hybrid policy: preserve every rule alert; ML may only raise a Low result to Medium.
- False-positive guardrail: no more than 0.50 percentage points above rules-only validation FPR (or 3.00% total, whichever is higher).
- Decision threshold: 0.995.

## Internal validation

| Method | N | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | 10806 | 789 | 10 | 5948 | 4059 | 98.75% | 16.27% | 0.17% | 27.94% |
| Hybrid | 10806 | 4139 | 11 | 5947 | 709 | 99.73% | 85.38% | 0.18% | 92.00% |

This is a calibration result, not an independent product-performance claim.

## Source counts

```json
{
  "authority-audit-bhs-holiday-package": 2,
  "authority-audit-de-family": 2,
  "authority-audit-en-usps": 2,
  "authority-audit-fr-smishing": 2,
  "authority-audit-nl-ideal": 2,
  "authority-bhs-road-fine": 3,
  "authority-bhs-whatsapp-vote": 3,
  "authority-de-bank-tan": 3,
  "authority-de-court-debt": 3,
  "authority-en-ftc-tax-refund": 3,
  "authority-en-ftc-toll": 3,
  "authority-fr-critair": 2,
  "authority-fr-critair-variant": 2,
  "authority-nl-dpd-postcode": 3,
  "authority-nl-foreign-login": 3,
  "authority-scam-bosnian-croatian-serbian": 10,
  "authority-scam-dutch": 9,
  "authority-scam-french": 8,
  "authority-scam-german": 10,
  "dortmund-chat-2.0": 3521,
  "dutch-whatsapp-berntzen": 636,
  "english-smishing-5971": 801,
  "french-88milsms": 9905,
  "imc25-smishing": 23004,
  "sarajevo-sms-1.1": 9789,
  "smishx": 301,
  "spaphish-v5": 1395,
  "uci-sms-spam": 4517,
  "user-scams": 21
}
```
