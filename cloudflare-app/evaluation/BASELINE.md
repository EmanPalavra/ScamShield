# ScamShield scoring baseline

Generated: 2026-07-27T00:01:56.814Z

This report evaluates the local message scoring rules only. A score of 34 or more is treated as an alert
(Medium or High risk). URL reputation providers and deep-scan network checks are deliberately excluded so the run is
deterministic and does not transmit dataset URLs.

## Overall

| Group | N | Scam | Legit | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| All samples | 31446 | 1890 | 29556 | 90.02% | 24.34% | 0.17% | 38.32% |

## Security-focused view

This view excludes positive samples labelled only as generic advertising spam. Legitimate negatives remain included,
so precision and false-positive rate are not made easier.

The authority-sourced reference set is a development regression set, not an independent performance estimate.

| Group | N | Scam | Legit | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Security scams + all legitimate samples | 30660 | 1104 | 29556 | 87.41% | 32.07% | 0.17% | 46.92% |
| Authority-sourced reference set | 75 | 75 | 0 | 100.00% | 98.67% | N/A | 99.33% |

## By language

| Group | N | Scam | Legit | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Bosnian / Croatian / Serbian | 9807 | 18 | 9789 | 100.00% | 100.00% | 0.00% | 100.00% |
| Dutch | 653 | 17 | 636 | 100.00% | 100.00% | 0.00% | 100.00% |
| English | 6133 | 1092 | 5041 | 99.65% | 25.82% | 0.02% | 41.02% |
| French | 9919 | 14 | 9905 | 93.33% | 100.00% | 0.01% | 96.55% |
| German | 3539 | 18 | 3521 | 100.00% | 94.44% | 0.00% | 97.14% |
| Spanish | 1395 | 731 | 664 | 69.57% | 15.32% | 7.38% | 25.11% |

## By source

| Group | N | Scam | Legit | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| authority-audit-bhs-holiday-package | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-audit-de-family | 2 | 2 | 0 | 100.00% | 50.00% | N/A | 66.67% |
| authority-audit-en-usps | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-audit-fr-smishing | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-audit-nl-ideal | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-bhs-road-fine | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-bhs-whatsapp-vote | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-de-bank-tan | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-de-court-debt | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-en-ftc-tax-refund | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-en-ftc-toll | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-fr-critair | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-fr-critair-variant | 2 | 2 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-nl-dpd-postcode | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-nl-foreign-login | 3 | 3 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-scam-bosnian-croatian-serbian | 10 | 10 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-scam-dutch | 9 | 9 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-scam-french | 8 | 8 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| authority-scam-german | 10 | 10 | 0 | 100.00% | 100.00% | N/A | 100.00% |
| dortmund-chat-2.0 | 3521 | 0 | 3521 | N/A | N/A | 0.00% | N/A |
| dutch-whatsapp-berntzen | 636 | 0 | 636 | N/A | N/A | 0.00% | N/A |
| english-smishing-5971 | 945 | 421 | 524 | 100.00% | 36.10% | 0.00% | 53.05% |
| french-88milsms | 9905 | 0 | 9905 | 0.00% | N/A | 0.01% | N/A |
| sarajevo-sms-1.1 | 9789 | 0 | 9789 | N/A | N/A | 0.00% | N/A |
| spaphish-v5 | 1395 | 731 | 664 | 69.57% | 15.32% | 7.38% | 25.11% |
| uci-sms-spam | 5159 | 642 | 4517 | 99.04% | 16.04% | 0.02% | 27.61% |
| user-scams | 21 | 21 | 0 | 100.00% | 90.48% | N/A | 95.00% |

## By scam type

"Detection recall" asks whether the sample raised any alert. The three "Type" columns are stricter one-vs-rest
classification metrics and require ScamShield to also name the exact annotated category.

| Scam type | N | Detection recall | Type precision | Type recall | Type FPR |
|---|---:|---:|---:|---:|---:|
| Account takeover / phishing | 1032 | 27.62% | 94.81% | 7.07% | 0.01% |
| Brand impersonation / fake charge | 18 | 100.00% | 19.15% | 100.00% | 0.24% |
| Check / mobile-deposit scam | 1 | 100.00% | 100.00% | 100.00% | 0.00% |
| Delivery / postal scam | 29 | 100.00% | 58.00% | 100.00% | 0.07% |
| Document / SMS phishing | 1 | 100.00% | 25.00% | 100.00% | 0.01% |
| Generic SMS spam | 786 | 13.49% | N/A | 0.00% | 0.00% |
| Gift-card impersonation scam | 1 | 100.00% | 100.00% | 100.00% | 0.00% |
| Identity / verification phishing | 2 | 100.00% | 100.00% | 100.00% | 0.00% |
| Investment / crypto scam | 2 | 100.00% | 66.67% | 100.00% | 0.00% |
| Job scam | 4 | 75.00% | 100.00% | 75.00% | 0.00% |
| Marketplace / payment scam | 4 | 75.00% | 100.00% | 75.00% | 0.00% |
| Prize / advance-fee scam | 2 | 100.00% | 1.02% | 100.00% | 0.62% |
| Renewal / subscription phishing | 1 | 100.00% | 50.00% | 100.00% | 0.00% |
| Romance / impersonation scam | 6 | 83.33% | 100.00% | 83.33% | 0.00% |
| Verification-code theft | 1 | 100.00% | 100.00% | 100.00% | 0.00% |

## Threshold calibration

- Current alert threshold 34: recall 24.34%, precision 90.02%, FPR 0.17%.
- Internal calibration/hashed split: 25102/6344. Authority examples remain
  calibration-only; public corpora use a deterministic sample-ID split.
- Best calibration F1: threshold 15 (F1 63.50%, recall 59.60%, FPR 1.79%).
- Highest calibration recall with FPR <= 5%: threshold 11 (recall 70.90%, precision 50.45%, FPR 4.44%).
- Internal hashed subset at candidate threshold 11: recall 72.99%, precision 52.52%, FPR 4.26%, F1 61.09%.

This internal report has influenced rule development and must not be presented as independent performance. Use
`FINAL_HOLDOUT.md` for the post-model independent estimate. Do not change the production threshold from this report
alone. UCI spam is broader than fraud/scam, while the user collection is user-reported rather than independently
adjudicated.

## Errors to review

- False positives: 51. Highest-scoring IDs: spaphish-e71e326d9a82780e9ff6f35a7b8744b8f57bba0e8225625b12191b1bb2a8d51e (67), spaphish-cbc488066f1c4cb47ae87b864bb4a7f976e791cbffc08221ec2a8e5a11d7253f (67), spaphish-998dd9aa1e432903fba44ec2230ee908f630ccbb3d5a5ce332bb9d00741fceaf (64), spaphish-4e8804fbf811e5a3f2bf9d229ca29d1082d88468f90bb719c7deabf654154475 (62), spaphish-d236fc0c406a86876280002f3071acee807fe4341dbd2d968aa91bcce698b490 (55), spaphish-df7e638f1593b2e928b1325ecfaedda559ae783489229333e515ad33d61322e1 (53), spaphish-ce6e979fb4090bb11a4c5443806ce2915ed163a75cc5de6ceb11609276708bb0 (52), spaphish-c8cc21baf3d3d19e1ef8b07d31e6bcc3f195d82c957cde222dcb4f1da624aafa (51), spaphish-cd3c3c224ca2ad33e793e5a6d8df9287a261303ffed4bbee85464aefaf03015c (50), spaphish-5739a328f2379bba844c7afbc5b847e833815b94dc381e33d4848b541844adec (50), spaphish-fb899c1f4446d588f427f54f31d27fab17d22fdf9a6528d7dc9a83c4bfa9059b (49), spaphish-074b5674d6c031f77f55a0ce6d224e5b593f5606b7c4cb7ac0a6d966bd3d4dc1 (49), spaphish-a0c6ae180ad809ea3d0d739212866230688bc79f788950c5452e4413e0a2a642 (49), spaphish-599977b9d398fa546501d065fa651c15f07fc940aa85d637aa7bb5cd20d7e058 (49), spaphish-a7b8a3cc19b159e7d743e39cd25c09167f8a07ba1c048194e5a303f97d5ee1f7 (49), spaphish-56f4b2f13ecbf325c2e9efb75bdcc495d1daea4a492c31708814fac8fa9fa19f (49), spaphish-a3dcd6664939567599d50ceb21b388bdfc82e4ea0dd084b9b8e8284939718bfe (49), spaphish-2ae4a78c10ce9562077345e3c8004b32e18599f8b6419a667062360723e07f64 (47), uci-sms-8060a63c985facc2 (46), spaphish-6f524dede31e318aa5ba9ef81b8397363a2cacbd8d6cf1ab9e2d55a8be98d8a6 (46).
- False negatives: 1430. Lowest-scoring IDs: uci-sms-14890ae324797db0 (4), uci-sms-5c976c2e582b3a13 (4), uci-sms-b5e70f7f0508003e (4), uci-sms-6ff46e4c7a354f9a (4), uci-sms-1c0299d2ffd2b108 (4), uci-sms-569634cbc640b851 (4), uci-sms-e47ed9297adb256a (4), uci-sms-53acf58c4265ae40 (4), uci-sms-59b564d8ba6c7955 (4), uci-sms-8c4285d347ba9297 (4), uci-sms-5484d7933dc13b98 (4), uci-sms-528a9ebfd0a37108 (4), uci-sms-520d1b988b7235a6 (4), uci-sms-21a2cc1b73ae73a2 (4), uci-sms-7b4e8d64c57d6e3f (4), uci-sms-a23e7b3ce8bee590 (4), uci-sms-1f5448792ed1eff1 (4), uci-sms-ea3a1bfbd3dc361c (4), uci-sms-7963127fbdc8c2fe (4), uci-sms-b806e655c8d8a1a5 (4).

Raw messages and per-sample results are git-ignored because they may contain user-reported or copyrighted content.
