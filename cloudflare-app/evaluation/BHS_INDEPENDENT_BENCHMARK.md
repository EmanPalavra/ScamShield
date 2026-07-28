# Frozen BHS benchmark

Generated: 2026-07-28T19:58:00.821Z

Frozen before model: `local-logreg-766c84b515acc503`

Evaluated model: `local-logreg-07c7960d472167ac`

| Tier | Scam | Legitimate | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Authority real-world | 25 | 600 | 9 | 0 | 600 | 16 | 100.0% | 36.0% | 0.0% | 52.9% |
| Verbatim authority screenshots/quotes | 19 | 600 | 9 | 0 | 600 | 10 | 100.0% | 47.4% | 0.0% | 64.3% |
| Source-grounded synthetic challenge | 75 | 600 | 18 | 0 | 600 | 57 | 100.0% | 24.0% | 0.0% | 38.7% |
| Combined | 100 | 600 | 27 | 0 | 600 | 73 | 100.0% | 27.0% | 0.0% | 42.5% |

The authority and synthetic tiers are intentionally reported separately. The combined row is useful for regression
testing, but must not be presented as a real-world population estimate.

## Limitations

- Only authority-verbatim rows are direct transcriptions of observed scam messages.
- Authority-described rows summarize campaigns explicitly reported by the cited institution.
- The 75 source-grounded challenge rows are synthetic and are reported separately from real-world rows.
- Some real campaign families influenced rules before this formal freeze; the report must not call the real-world tier fully untouched.
- Legitimate controls are authentic Bosnian SMS messages from the Sarajevo Corpus and are excluded from model training by complete normalized-template group.
