import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis } from "../worker/scanner/message-analysis.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const rawDir = path.join(evaluationDir, "data", "raw");
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const resultsDir = path.join(evaluationDir, "results");
const manifestPath = path.join(evaluationDir, "frozen-holdout-manifest.json");
const threshold = 34;

interface FrozenSource {
  id: string;
  sha256: string;
  localFile: string;
}

interface Manifest {
  frozenAt: string;
  policy: string;
  sources: FrozenSource[];
}

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
      } else if (character === "\"") {
        quoted = false;
      } else {
        cell += character;
      }
    } else if (character === "\"") {
      quoted = true;
    } else if (character === ",") {
      row.push(cell);
      cell = "";
    } else if (character === "\n") {
      row.push(cell.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += character;
    }
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

function normalizeText(text: string) {
  return text.normalize("NFKC").toLocaleLowerCase().replace(/\s+/g, " ").trim();
}

function textHash(text: string) {
  return createHash("sha256").update(normalizeText(text)).digest("hex");
}

function score(text: string) {
  return messageAnalysis(text, extractUrls(text)).score;
}

function divide(numerator: number, denominator: number) {
  return denominator ? numerator / denominator : null;
}

function percent(value: number | null) {
  return value === null ? "N/A" : `${(value * 100).toFixed(2)}%`;
}

function wilson(successes: number, total: number) {
  if (!total) return null;
  const z = 1.959963984540054;
  const observed = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = (observed + (z * z) / (2 * total)) / denominator;
  const margin = (
    z * Math.sqrt((observed * (1 - observed)) / total + (z * z) / (4 * total * total))
  ) / denominator;
  return [Math.max(0, center - margin), Math.min(1, center + margin)] as const;
}

function recallMetrics(scores: number[]) {
  const detected = scores.filter((value) => value >= threshold).length;
  return {
    samples: scores.length,
    detected,
    recall: divide(detected, scores.length),
    confidence95: wilson(detected, scores.length),
  };
}

function binaryMetrics(entries: Array<{ label: "scam" | "legitimate"; score: number }>) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const entry of entries) {
    const expected = entry.label === "scam";
    const predicted = entry.score >= threshold;
    if (expected && predicted) tp += 1;
    else if (expected) fn += 1;
    else if (predicted) fp += 1;
    else tn += 1;
  }
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  return {
    samples: entries.length,
    scam: tp + fn,
    legitimate: tn + fp,
    tp,
    fp,
    tn,
    fn,
    precision,
    recall,
    falsePositiveRate: divide(fp, fp + tn),
    f1: precision !== null && recall !== null && precision + recall
      ? (2 * precision * recall) / (precision + recall)
      : null,
    recallConfidence95: wilson(tp, tp + fn),
    falsePositiveRateConfidence95: wilson(fp, fp + tn),
  };
}

const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
const rawBySource = new Map<string, string>();
for (const source of manifest.sources) {
  const content = await readFile(path.join(rawDir, source.localFile));
  const actualHash = createHash("sha256").update(content).digest("hex");
  if (actualHash !== source.sha256) {
    throw new Error(`${source.id} is not the frozen file: expected ${source.sha256}, got ${actualHash}.`);
  }
  rawBySource.set(source.id, content.toString("utf8"));
}

const calibrationHashes = new Set(
  (await readFile(generatedPath, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => textHash((JSON.parse(line) as { text: string }).text)),
);

const smishxRows = records(rawBySource.get("smishx") ?? "");
const novelSmishx = smishxRows.filter((row) => row.SMS && !calibrationHashes.has(textHash(row.SMS)));
const smishxOverlap = smishxRows.length - novelSmishx.length;
const smishxPrimary = novelSmishx
  .filter((row) => row.label === "smishing" || row.label === "legitimate")
  .map((row) => ({
    label: row.label === "smishing" ? "scam" as const : "legitimate" as const,
    score: score(row.SMS),
  }));
const smishxMetrics = binaryMetrics(smishxPrimary);
const smishxSpamScores = novelSmishx.filter((row) => row.label === "spam").map((row) => score(row.SMS));
const smishxSpamAlertRate = recallMetrics(smishxSpamScores);

const imcRows = records(rawBySource.get("imc25-smishing") ?? "");
const novelImc = imcRows.filter((row) => row.text && !calibrationHashes.has(textHash(row.text)));
const imcOverlap = imcRows.length - novelImc.length;
const scoredImc = novelImc.map((row) => ({
  language: row.language || "Unspecified",
  scamType: row.scam_type || "Unspecified",
  score: score(row.text),
}));
const clearlyMaliciousTypes = new Set([
  "banking",
  "delivery",
  "government",
  "telecom",
  "hey mum/dad",
  "others",
]);
const imcAll = recallMetrics(scoredImc.map((row) => row.score));
const imcSecurity = recallMetrics(
  scoredImc.filter((row) => clearlyMaliciousTypes.has(row.scamType.toLowerCase())).map((row) => row.score),
);

const languageGroups = [
  ["English", ["English"]],
  ["Spanish", ["Spanish"]],
  ["Dutch", ["Dutch"]],
  ["French", ["French"]],
  ["German", ["German"]],
  ["BHS", ["Bosnian", "Croatian", "Serbian"]],
] as const;
const imcByLanguage = Object.fromEntries(languageGroups.map(([label, languages]) => [
  label,
  recallMetrics(
    scoredImc
      .filter((row) => (languages as readonly string[]).includes(row.language))
      .filter((row) => clearlyMaliciousTypes.has(row.scamType.toLowerCase()))
      .map((row) => row.score),
  ),
]));
const imcByType = Object.fromEntries(
  [...new Set(scoredImc.map((row) => row.scamType))].sort().map((scamType) => [
    scamType,
    recallMetrics(scoredImc.filter((row) => row.scamType === scamType).map((row) => row.score)),
  ]),
);

function interval(value: readonly [number, number] | null) {
  return value ? `${percent(value[0])}–${percent(value[1])}` : "N/A";
}

const languageLines = [
  "| Language | N | Detected | Recall | 95% CI |",
  "|---|---:|---:|---:|---:|",
  ...Object.entries(imcByLanguage).map(([language, metrics]) =>
    `| ${language} | ${metrics.samples} | ${metrics.detected} | ${percent(metrics.recall)} | ${interval(metrics.confidence95)} |`
  ),
];
const typeLines = [
  "| Report category | N | Detected | Alert rate | 95% CI |",
  "|---|---:|---:|---:|---:|",
  ...Object.entries(imcByType).map(([type, metrics]) =>
    `| ${type} | ${metrics.samples} | ${metrics.detected} | ${percent(metrics.recall)} | ${interval(metrics.confidence95)} |`
  ),
];

const report = `# Historical pre-model external holdout

Generated: ${new Date().toISOString()}
Frozen: ${manifest.frozenAt}
Alert threshold: ${threshold}

This report predates the local statistical model. Its sources were subsequently used for model training, so the
numbers below are retained for reproducibility and must not be presented as post-model unseen performance. Input files
remain pinned to exact repository commits and verified by SHA-256.

## Primary binary benchmark: novel SmishX rows

Only manually labelled smishing and legitimate messages are used. Generic spam is reported separately and does not
count as either a security success or a false positive.

| N | Scam | Legit | Precision | Recall | FPR | F1 |
|---:|---:|---:|---:|---:|---:|---:|
| ${smishxMetrics.samples} | ${smishxMetrics.scam} | ${smishxMetrics.legitimate} | ${percent(smishxMetrics.precision)} | ${percent(smishxMetrics.recall)} | ${percent(smishxMetrics.falsePositiveRate)} | ${percent(smishxMetrics.f1)} |

- Recall 95% confidence interval: ${interval(smishxMetrics.recallConfidence95)}.
- FPR 95% confidence interval: ${interval(smishxMetrics.falsePositiveRateConfidence95)}.
- Excluded exact calibration overlaps: ${smishxOverlap} of ${smishxRows.length}.
- Novel generic-spam alert rate: ${percent(smishxSpamAlertRate.recall)} (${smishxSpamAlertRate.detected}/${smishxSpamAlertRate.samples}); excluded from primary F1.

## Independent real-world smishing recall: IMC 2025

This source contains reported smishing positives, not legitimate negatives, so it can measure recall but cannot
honestly measure precision or FPR. The security-focused view excludes rows categorized as generic spam, wrong number,
or unspecified.

- All novel reported messages: ${percent(imcAll.recall)} (${imcAll.detected}/${imcAll.samples}), 95% CI ${interval(imcAll.confidence95)}.
- Security-focused categories: ${percent(imcSecurity.recall)} (${imcSecurity.detected}/${imcSecurity.samples}), 95% CI ${interval(imcSecurity.confidence95)}.
- Excluded exact calibration overlaps: ${imcOverlap} of ${imcRows.length}.

### Security recall by language

${languageLines.join("\n")}

### Alert rate by source category

${typeLines.join("\n")}

## Interpretation

The SmishX result is the primary independent precision/recall/F1 estimate. IMC 2025 is the stronger multilingual
recall stress test because it contains tens of thousands of recent public user reports. Small language groups have
wide confidence intervals and must not be presented as precise per-language performance.
`;

const result = {
  generatedAt: new Date().toISOString(),
  frozenAt: manifest.frozenAt,
  threshold,
  smishx: {
    exactOverlapsExcluded: smishxOverlap,
    primary: smishxMetrics,
    genericSpamAlertRate: smishxSpamAlertRate,
  },
  imc25: {
    exactOverlapsExcluded: imcOverlap,
    allReported: imcAll,
    securityFocused: imcSecurity,
    byLanguage: imcByLanguage,
    byType: imcByType,
  },
};

await mkdir(resultsDir, { recursive: true });
await writeFile(path.join(resultsDir, "frozen-holdout.json"), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(path.join(evaluationDir, "FROZEN_HOLDOUT.md"), report);
console.log(report);
