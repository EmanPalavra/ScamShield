# Local ML model training

Generated: 2026-07-27T02:34:25.312Z
Model: local-logreg-07c7960d472167ac

- Algorithm: quantized feature-hashed logistic regression with AdaGrad.
- Features: normalized character 3/4-grams, word unigrams/bigrams, and bounded structural indicators.
- Training/validation: 39792/9967, deterministic 80/20 text-hash split after exact deduplication.
- Training positives/negatives: 18835/20957.
- Legitimate language-holdout rows excluded before training: 2200.
- Retained multilingual rows excluded before training: 4022.
- Label conflicts excluded: 0.
- Model size: 16,384 weight bytes before Base64.
- Hybrid policy: preserve every rule alert; ML may only raise a Low result to Medium.
- False-positive guardrail: no more than 0.50 percentage points above rules-only validation FPR (or 3.00% total, whichever is higher).
- Decision threshold: 0.980.

## Internal validation

| Method | N | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | 9967 | 855 | 7 | 5285 | 3820 | 99.19% | 18.29% | 0.13% | 30.88% |
| Hybrid | 9967 | 4288 | 12 | 5280 | 387 | 99.72% | 91.72% | 0.23% | 95.55% |

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
  "authority-derived-de-bhs-scam": 160,
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
  "dortmund-chat-2.0": 2772,
  "dutch-whatsapp-berntzen": 79,
  "english-smishing-5971": 731,
  "french-88milsms": 9115,
  "imc25-smishing": 21454,
  "sarajevo-sms-1.1": 9179,
  "smishx": 377,
  "spaphish-v5": 995,
  "synthetic-de-bhs-hard-negative": 80,
  "synthetic-multilingual-authority-derived": 608,
  "synthetic-multilingual-hard-negative": 360,
  "uci-sms-spam": 3818,
  "user-scams": 21
}
```
