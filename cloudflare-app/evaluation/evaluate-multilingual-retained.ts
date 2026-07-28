import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis } from "../worker/scanner/message-analysis.ts";
import { mlModel } from "../worker/scanner/ml-model.ts";
import type { EvaluationSample } from "./dataset-types.ts";
import {
  retainedFingerprint,
  retainedLanguages,
  selectRetainedBenchmark,
  type RetainedLanguage,
  type RetainedSample,
} from "./multilingual-retained-benchmark.ts";

interface Metric {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}
interface Manifest {
  status: string;
  frozenAt: string;
  sourceSha256: string;
  splitFingerprint: string;
  previousModelVersion: string;
  previousMetrics: Record<RetainedLanguage, Metric>;
  limitations: string[];
}

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const imcPath = path.join(evaluationDir, "data", "raw", "imc25-smishing.csv");
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const manifestPath = path.join(evaluationDir, "multilingual-retained-manifest.json");
const reportPath = path.join(evaluationDir, "MULTILINGUAL_RETAINED.md");
const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
const imc = await readFile(imcPath, "utf8");
const generated = (await readFile(generatedPath, "utf8"))
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as EvaluationSample);
const samples = selectRetainedBenchmark(imc, generated);
if (createHash("sha256").update(imc).digest("hex") !== manifest.sourceSha256) {
  throw new Error("Retained IMC source hash changed.");
}
if (retainedFingerprint(samples) !== manifest.splitFingerprint) {
  throw new Error("Retained multilingual split changed.");
}

function metrics(rows: RetainedSample[]): Metric {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const row of rows) {
    const predicted = messageAnalysis(row.text, extractUrls(row.text)).score >= 34;
    if (row.label && predicted) tp += 1;
    else if (row.label) fn += 1;
    else if (predicted) fp += 1;
    else tn += 1;
  }
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = (2 * precision * recall) / Math.max(Number.EPSILON, precision + recall);
  return { tp, fp, tn, fn, precision, recall, f1 };
}
const current = Object.fromEntries(retainedLanguages.map((language) => [
  language,
  metrics(samples.filter((sample) => sample.language === language)),
])) as Record<RetainedLanguage, Metric>;
const percent = (value: number) => `${(value * 100).toFixed(1)}%`;
const signedPoints = (value: number) => `${value >= 0 ? "+" : ""}${(value * 100).toFixed(1)} pp`;
const lines = retainedLanguages.map((language) => {
  const previous = manifest.previousMetrics[language];
  const next = current[language];
  const count = next.tp + next.fp + next.tn + next.fn;
  return `| ${language} | ${count} | ${percent(previous.f1)} | ${percent(next.f1)} | ${signedPoints(next.f1 - previous.f1)} | ${percent(next.precision)} | ${percent(next.recall)} |`;
});
const report = `# Retained multilingual benchmark

Generated: ${new Date().toISOString()}
Previous model: ${manifest.previousModelVersion}
Current model: ${mlModel.version}

| Language | N | Previous F1 | Current F1 | Change | Current precision | Current recall |
|---|---:|---:|---:|---:|---:|---:|
${lines.join("\n")}

## Integrity

- Frozen before the multilingual training expansion: ${manifest.frozenAt}.
- Positive rows are original-language IMC reports; negative rows are authentic language corpora.
- Complete normalized-template groups are excluded from the current model's training.
- The previous model had already seen IMC positives, so this is a conservative retained comparison, not a newly untouched benchmark.
- Threshold selection used only the large internal validation split, not this benchmark.
- BHS rules were calibrated after the first retained score because only 11 positive messages exist. Its row is a
  transparent development comparison, not independent evidence.
- BHS remains too small for a stable population-level F1 claim.
`;
await writeFile(reportPath, report);
console.log(report);
