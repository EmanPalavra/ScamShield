# Scoring evaluation

This folder measures ScamShield's local message rules against real-world corpora. It never calls URL reputation
providers or the deep-scan API, so evaluation messages and URLs are not transmitted to third parties.

## Run

From `cloudflare-app`:

```text
pnpm run evaluate:download
pnpm run evaluate
pnpm run evaluate:holdout
pnpm run evaluate:train-model
pnpm run evaluate:final-holdout
```

`evaluate:download` retrieves only the sources listed in `sources.json` from their official repositories. Published
hashes are verified where available. `evaluate:build` also reads the repository-root `Scams.txt` and the attributed
authority examples. Raw and normalized message content is git-ignored; the safe aggregate report is written to
`evaluation/BASELINE.md`.

`evaluate:holdout` reproduces the historical pre-model benchmark. Those sources later became model-training data, so
`FROZEN_HOLDOUT.md` must not be presented as post-model unseen evidence.

`evaluate:train-model` deterministically builds the compact, quantized local classifier and its calibration report.
`evaluate:final-holdout` compares rules-only and hybrid behavior on sources frozen after the model and threshold were
locked. It writes aggregate-only results to `FINAL_HOLDOUT.md`; those results must not be used to retune this model.

Set a different candidate alert threshold without changing production code:

```text
SCAMSHIELD_EVAL_THRESHOLD=20 pnpm run evaluate:score
```

On PowerShell:

```text
$env:SCAMSHIELD_EVAL_THRESHOLD=20; pnpm run evaluate:score
```

## Sources and labels

| Source | Role | Label quality | Language |
|---|---|---|---|
| User `Scams.txt` | Modern, category-specific scam examples | User-reported; not independently adjudicated | English |
| UCI SMS Spam Collection | Broad SMS spam/ham robustness and legitimate negatives | Public corpus labels, CC BY 4.0 | English |
| SpaPhish v5 | Real phishing and legitimate email | Three expert labels with adjudication, CC BY 4.0 | Spanish |
| English SMS phishing 5971 | Modern smishing, spam, and legitimate SMS | Public corpus labels, CC BY 4.0 | English |
| Sarajevo SMS 1.1 | Authentic legitimate SMS negatives | Voluntarily donated, CC BY 4.0 | Bosnian |
| 88milSMS | Authentic legitimate SMS negatives | Anonymized corpus, CC BY 4.0 | French |
| Dortmund Chat 2.0 | Authentic legitimate chat negatives | Public corpus, CC BY 4.0 | German |
| WhatsApp Corpus Berntzen | Authentic legitimate chat negatives | Consented corpus, CC BY 4.0 | Dutch |
| Consumer protection, police, FTC, and CERT examples | Short redacted or authority-described scam positives with source URL per sample | Authority-confirmed/authority-described | English, German, French, Dutch, BHS |
| IMC 2025 public smishing reports | Model training; historical pre-model benchmark | Research-labeled public reports, CC BY 4.0 | Multilingual |
| SmishX | Model training; historical pre-model benchmark | Manually re-labeled, MIT | English |
| MOZ-Smishing | Final untouched binary generalization check | Crowd-sourced, research-labeled | Portuguese (Mozambique) |
| SmishTank | Final untouched positive-only recall check | Community-submitted suspected smishing | Primarily English |

The exact URLs, expected counts, and licenses are recorded in `sources.json`. User items 17 and 20 are retained as
deliberately difficult examples but remain marked user-reported because their text could also resemble legitimate
notifications or outreach.

## Metric definitions

- **Precision:** among messages that raised an alert, the fraction truly labeled scam/phishing.
- **Recall:** among scam/phishing messages, the fraction that raised an alert.
- **False-positive rate (FPR):** among legitimate messages, the fraction that incorrectly raised an alert.
- **Detection recall by scam type:** whether the message raised any alert, even if the exact category name differed.
- **Type metrics:** stricter one-vs-rest metrics that also require the exact scam category.

Threshold selection uses explicit calibration assignments for authority examples and a deterministic 80/20 split for
public corpora. Authority examples inspected during rule development remain calibration-only and are never presented
as unseen evidence.

## Limits

- UCI `spam` includes advertising and prize spam that is not always fraud. It is useful for robustness, but should not
  alone determine ScamShield's production threshold.
- SpaPhish is binary phishing/legitimate data. It does not provide ScamShield's detailed scam taxonomy, so its
  phishing rows are mapped to the broad `Account takeover / phishing` category.
- English, German, French, Dutch, and BHS authority scam-positive sets are small and were used while refining the rules. Their current
  100% recall is an in-sample regression result, not proof of 100% detection on unseen scams.
- The large multilingual corpora provide strong legitimate-message coverage, but more independently collected scam
  positives are still required for a trustworthy per-language holdout benchmark.
- English and UCI `spam` rows include advertising that is not necessarily fraud; SpamShield deliberately prioritizes
  scam precision over classifying every promotional message as a security threat.
- Synthetic or translated samples must never be reported as authentic messages.
- `FINAL_HOLDOUT.md` is the post-model non-inflated result. It records both the English recall gain and the weak
  Portuguese generalization instead of hiding an unfavorable result.
- `FROZEN_HOLDOUT.md`, authority-reference recall, internal model validation, and the ordinary baseline remain useful
  regression/calibration checks, but they are not independent post-model performance estimates.
