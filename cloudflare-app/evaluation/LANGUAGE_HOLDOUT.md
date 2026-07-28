# Retired per-language holdout

This benchmark was retired on 2026-07-27 and its earlier scores must not be used.

The SpamHunter file's `SMS Translation` column contains English translations, while `SMS Language`
describes the language of the original message. The retired evaluator mistakenly treated those
translations as original German, French, and Dutch text. Its language-specific results were therefore
invalid. The six BHS positives were also too small and included short, ambiguous fragments.

ScamShield now treats those records only as corpus research material. A future language benchmark must:

- score original-language text, not translations;
- remain untouched until rules and model training are complete;
- contain independently sourced scam positives and authentic legitimate controls;
- report sample counts and uncertainty, especially for German and BHS.

The current DE/BHS regression suite and internal model validation are calibration checks, not independent
claims about real-world F1.
