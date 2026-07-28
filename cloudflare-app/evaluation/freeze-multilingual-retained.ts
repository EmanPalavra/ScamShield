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
  type RetainedSample,
} from "./multilingual-retained-benchmark.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const imcPath = path.join(evaluationDir, "data", "raw", "imc25-smishing.csv");
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const manifestPath = path.join(evaluationDir, "multilingual-retained-manifest.json");
const imc = await readFile(imcPath, "utf8");
const generated = (await readFile(generatedPath, "utf8"))
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as EvaluationSample);
const samples = selectRetainedBenchmark(imc, generated);

function metrics(rows: RetainedSample[]) {
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

const manifest = {
  status: "frozen-before-multilingual-expansion",
  frozenAt: new Date().toISOString(),
  alertThreshold: 34,
  sourceSha256: createHash("sha256").update(imc).digest("hex"),
  splitFingerprint: retainedFingerprint(samples),
  previousModelVersion: mlModel.version,
  sampleCounts: Object.fromEntries(retainedLanguages.map((language) => [
    language,
    {
      scam: samples.filter((sample) => sample.language === language && sample.label === 1).length,
      legitimate: samples.filter((sample) => sample.language === language && sample.label === 0).length,
    },
  ])),
  previousMetrics: Object.fromEntries(retainedLanguages.map((language) => [
    language,
    metrics(samples.filter((sample) => sample.language === language)),
  ])),
  limitations: [
    "The previous model had already seen IMC positives before this split was introduced.",
    "The split is retained and source/template-separated for the new model, but is not a newly untouched corpus.",
    "BHS has only the original Croatian and Serbian positives available in IMC and therefore remains a small sample.",
  ],
};
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
console.log(JSON.stringify(manifest, null, 2));
