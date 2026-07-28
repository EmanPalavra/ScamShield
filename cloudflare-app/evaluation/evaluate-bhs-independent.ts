import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis } from "../worker/scanner/message-analysis.ts";
import { mlModel } from "../worker/scanner/ml-model.ts";
import {
  bhsBenchmarkFingerprint,
  selectBhsIndependentBenchmark,
} from "./bhs-independent-benchmark.ts";
import type { EvaluationSample } from "./dataset-types.ts";

interface Manifest {
  status: "frozen-unscored" | "frozen-scored";
  frozenAt: string;
  frozenBeforeModel: string;
  generatedDatasetSha256: string;
  fingerprint: string;
  limitations: string[];
}

interface Metric {
  samples: number;
  positives: number;
  negatives: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  falsePositiveRate: number;
  f1: number;
}

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const manifestPath = path.join(evaluationDir, "bhs-independent-manifest.json");
const resultsDir = path.join(evaluationDir, "results");
const raw = await readFile(generatedPath, "utf8");
const generated = raw
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as EvaluationSample);
const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
const samples = selectBhsIndependentBenchmark(generated);

if (!["frozen-unscored", "frozen-scored"].includes(manifest.status)) {
  throw new Error(`Unexpected benchmark status: ${manifest.status}`);
}
if (createHash("sha256").update(raw).digest("hex") !== manifest.generatedDatasetSha256) {
  throw new Error("Generated dataset changed after the BHS benchmark was frozen.");
}
if (bhsBenchmarkFingerprint(samples) !== manifest.fingerprint) {
  throw new Error("BHS benchmark fingerprint changed after freeze.");
}

const scored = samples.map((sample) => ({
  ...sample,
  predictedScam: messageAnalysis(sample.text, extractUrls(sample.text)).score >= 34,
}));

function metric(rows: typeof scored): Metric {
  const tp = rows.filter((row) => row.label === "scam" && row.predictedScam).length;
  const fp = rows.filter((row) => row.label === "legitimate" && row.predictedScam).length;
  const tn = rows.filter((row) => row.label === "legitimate" && !row.predictedScam).length;
  const fn = rows.filter((row) => row.label === "scam" && !row.predictedScam).length;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return {
    samples: rows.length,
    positives: tp + fn,
    negatives: tn + fp,
    tp,
    fp,
    tn,
    fn,
    precision,
    recall,
    falsePositiveRate: fp + tn ? fp / (fp + tn) : 0,
    f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
  };
}

const negatives = scored.filter((row) => row.label === "legitimate");
const real = scored.filter((row) =>
  row.provenance === "authority-verbatim-redacted"
  || row.provenance === "authority-described"
);
const verbatim = scored.filter((row) => row.provenance === "authority-verbatim-redacted");
const challenge = scored.filter((row) => row.provenance === "source-grounded-synthetic");
const withSharedNegatives = (positives: typeof scored) => [...positives, ...negatives];
const countries = ["BA", "HR", "RS"] as const;

function positiveRecall(rows: typeof scored) {
  const detected = rows.filter((row) => row.predictedScam).length;
  return {
    samples: rows.length,
    detected,
    recall: rows.length ? detected / rows.length : 0,
  };
}

const result = {
  generatedAt: new Date().toISOString(),
  frozenAt: manifest.frozenAt,
  frozenBeforeModel: manifest.frozenBeforeModel,
  evaluatedModel: mlModel.version,
  threshold: 34,
  combined: metric(scored),
  realWorldTier: metric(withSharedNegatives(real)),
  verbatimOnlyTier: metric(withSharedNegatives(verbatim)),
  sourceGroundedChallengeTier: metric(withSharedNegatives(challenge)),
  realWorldRecallByCountry: Object.fromEntries(countries.map((country) => [
    country,
    positiveRecall(real.filter((row) => row.country === country)),
  ])),
  challengeRecallByCountry: Object.fromEntries(countries.map((country) => [
    country,
    positiveRecall(challenge.filter((row) => row.country === country)),
  ])),
  limitations: manifest.limitations,
};

const percent = (value: number) => `${(value * 100).toFixed(1)}%`;
const row = (label: string, value: Metric) =>
  `| ${label} | ${value.positives} | ${value.negatives} | ${value.tp} | ${value.fp} | ${value.tn} | ${value.fn} | ${percent(value.precision)} | ${percent(value.recall)} | ${percent(value.falsePositiveRate)} | ${percent(value.f1)} |`;
const report = `# Frozen BHS benchmark

Generated: ${result.generatedAt}

Frozen before model: \`${result.frozenBeforeModel}\`

Evaluated model: \`${result.evaluatedModel}\`

| Tier | Scam | Legitimate | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
${row("Authority real-world", result.realWorldTier)}
${row("Verbatim authority screenshots/quotes", result.verbatimOnlyTier)}
${row("Source-grounded synthetic challenge", result.sourceGroundedChallengeTier)}
${row("Combined", result.combined)}

The authority and synthetic tiers are intentionally reported separately. The combined row is useful for regression
testing, but must not be presented as a real-world population estimate.

## Limitations

${result.limitations.map((limitation) => `- ${limitation}`).join("\n")}
`;

await mkdir(resultsDir, { recursive: true });
await writeFile(path.join(resultsDir, "bhs-independent.json"), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(path.join(evaluationDir, "BHS_INDEPENDENT_BENCHMARK.md"), report);
console.log(report);
