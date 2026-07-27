import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis, messageRuleAnalysis } from "../worker/scanner/message-analysis.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const rawDir = path.join(evaluationDir, "data", "raw");
const sourcePath = path.join(rawDir, "moz-smishing.csv");
const smishTankPath = path.join(rawDir, "smishtank-final.csv");
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const reportPath = path.join(evaluationDir, "FINAL_HOLDOUT.md");

function parseCsv(text: string) {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === "\"" && text[index + 1] === "\"") {
        cell += "\"";
        index += 1;
      } else if (character === "\"") quoted = false;
      else cell += character;
    } else if (character === "\"") quoted = true;
    else if (character === ",") {
      row.push(cell);
      cell = "";
    } else if (character === "\n") {
      row.push(cell.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      cell = "";
    } else cell += character;
  }
  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

function records(text: string) {
  const rows = parseCsv(text.replace(/^\uFEFF/, ""));
  const headers = rows.shift();
  if (!headers) return [];
  return rows
    .filter((row) => row.some(Boolean))
    .map((row) => Object.fromEntries(headers.map((header, index) => [header, row[index] ?? ""])));
}

function normalizedHash(text: string) {
  const normalized = text.normalize("NFKC").toLocaleLowerCase().replace(/\s+/g, " ").trim();
  return createHash("sha256").update(normalized).digest("hex");
}

function metrics(rows: Array<{ label: 0 | 1; predicted: boolean }>) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const row of rows) {
    if (row.label && row.predicted) tp += 1;
    else if (row.label) fn += 1;
    else if (row.predicted) fp += 1;
    else tn += 1;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const fpr = fp / Math.max(1, fp + tn);
  const f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  return { tp, fp, tn, fn, precision, recall, fpr, f1 };
}

function percent(value: number) {
  return `${(value * 100).toFixed(2)}%`;
}

const trainingHashes = new Set<string>();
const generated = (await readFile(generatedPath, "utf8")).split(/\r?\n/).filter(Boolean);
for (const line of generated) {
  const row = JSON.parse(line) as { text: string };
  trainingHashes.add(normalizedHash(row.text));
}
for (const filename of ["imc25-smishing.csv", "smishx-holdout.csv"]) {
  for (const row of records(await readFile(path.join(rawDir, filename), "utf8"))) {
    const text = row.text || row.SMS;
    if (text) trainingHashes.add(normalizedHash(text));
  }
}

const sourceRows = records(await readFile(sourcePath, "utf8"))
  .filter((row) => row.text && ["Legitimate", "Smishing"].includes(row.label));
const overlapCount = sourceRows.filter((row) => trainingHashes.has(normalizedHash(row.text))).length;
const novel = sourceRows.filter((row) => !trainingHashes.has(normalizedHash(row.text)));
const scored = novel.map((row) => {
  const urls = extractUrls(row.text);
  return {
    label: row.label === "Smishing" ? 1 as const : 0 as const,
    ruleScore: messageRuleAnalysis(row.text, urls).score,
    hybridScore: messageAnalysis(row.text, urls).score,
  };
});
const rules = metrics(scored.map((row) => ({ label: row.label, predicted: row.ruleScore >= 34 })));
const hybrid = metrics(scored.map((row) => ({ label: row.label, predicted: row.hybridScore >= 34 })));
const absoluteF1Gain = hybrid.f1 - rules.f1;
const relativeF1Gain = rules.f1 ? absoluteF1Gain / rules.f1 : null;
const smishTankRows = records(await readFile(smishTankPath, "utf8")).filter((row) => row.Fulltext);
const smishTankOverlapCount = smishTankRows
  .filter((row) => trainingHashes.has(normalizedHash(row.Fulltext)))
  .length;
const smishTankNovel = smishTankRows
  .filter((row) => !trainingHashes.has(normalizedHash(row.Fulltext)))
  .map((row) => {
    const urls = extractUrls(row.Fulltext);
    return {
      ruleAlert: messageRuleAnalysis(row.Fulltext, urls).score >= 34,
      hybridAlert: messageAnalysis(row.Fulltext, urls).score >= 34,
    };
  });
const smishTankRuleHits = smishTankNovel.filter((row) => row.ruleAlert).length;
const smishTankHybridHits = smishTankNovel.filter((row) => row.hybridAlert).length;
const smishTankRuleRecall = smishTankRuleHits / Math.max(1, smishTankNovel.length);
const smishTankHybridRecall = smishTankHybridHits / Math.max(1, smishTankNovel.length);

const report = `# Final untouched holdout

Generated: ${new Date().toISOString()}

The model, threshold, integration policy, and application tests were locked before this dataset was scored.
No result below may be used to retune the model without retiring this dataset as an untouched holdout.

- Source: MOZ-Smishing (AfricaNLP 2025), crowd-sourced Mozambican mobile-money messages.
- Language/domain: Portuguese from Mozambique; intentionally outside ScamShield's primary trained languages.
- Raw rows: ${sourceRows.length}; exact overlaps with all training/calibration sources excluded: ${overlapCount}; evaluated: ${novel.length}.

| Method | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | ${rules.tp} | ${rules.fp} | ${rules.tn} | ${rules.fn} | ${percent(rules.precision)} | ${percent(rules.recall)} | ${percent(rules.fpr)} | ${percent(rules.f1)} |
| Hybrid local ML | ${hybrid.tp} | ${hybrid.fp} | ${hybrid.tn} | ${hybrid.fn} | ${percent(hybrid.precision)} | ${percent(hybrid.recall)} | ${percent(hybrid.fpr)} | ${percent(hybrid.f1)} |

- Absolute F1 change: ${absoluteF1Gain >= 0 ? "+" : ""}${(absoluteF1Gain * 100).toFixed(2)} percentage points.
- Relative F1 change: ${relativeF1Gain === null
  ? "not defined because the rules-only F1 was zero"
  : `${relativeF1Gain >= 0 ? "+" : ""}${(relativeF1Gain * 100).toFixed(2)}%`}.

This is a credible generalization check, not a claim that Portuguese is fully supported.

## English positive-only recall check

SmishTank contains community-submitted suspected smishing messages and no legitimate control class. It can measure
recall, but cannot honestly produce precision, FPR, or F1.

- Raw rows: ${smishTankRows.length}; exact overlaps excluded: ${smishTankOverlapCount}; evaluated: ${smishTankNovel.length}.

| Method | Detected | Missed | Recall |
|---|---:|---:|---:|
| Rules only | ${smishTankRuleHits} | ${smishTankNovel.length - smishTankRuleHits} | ${percent(smishTankRuleRecall)} |
| Hybrid local ML | ${smishTankHybridHits} | ${smishTankNovel.length - smishTankHybridHits} | ${percent(smishTankHybridRecall)} |

- Absolute recall change: ${(smishTankHybridRecall - smishTankRuleRecall) >= 0 ? "+" : ""}${((smishTankHybridRecall - smishTankRuleRecall) * 100).toFixed(2)} percentage points.
`;
await writeFile(reportPath, report);
console.log(report);
