import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis } from "../worker/scanner/message-analysis.ts";
import type { EvaluationSample, ScoredSample } from "./dataset-types.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const datasetPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const resultsDir = path.join(evaluationDir, "results");
const alertThreshold = Number(process.env.SCAMSHIELD_EVAL_THRESHOLD ?? 34);

interface Metrics {
  samples: number;
  positive: number;
  negative: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  falsePositiveRate: number | null;
  f1: number | null;
  accuracy: number | null;
}

function divide(numerator: number, denominator: number) {
  return denominator ? numerator / denominator : null;
}

function binaryMetrics(samples: ScoredSample[], threshold: number): Metrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const sample of samples) {
    const expected = sample.label === "scam";
    const predicted = sample.score >= threshold;
    if (expected && predicted) tp += 1;
    else if (!expected && predicted) fp += 1;
    else if (!expected) tn += 1;
    else fn += 1;
  }
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  return {
    samples: samples.length,
    positive: tp + fn,
    negative: tn + fp,
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
    accuracy: divide(tp + tn, samples.length),
  };
}

function categoryMetrics(samples: ScoredSample[], scamType: string, threshold: number) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const sample of samples) {
    const expected = sample.label === "scam" && sample.scamType === scamType;
    const predicted = sample.score >= threshold && sample.predictedScamType === scamType;
    if (expected && predicted) tp += 1;
    else if (!expected && predicted) fp += 1;
    else if (!expected) tn += 1;
    else fn += 1;
  }
  const typeSamples = samples.filter((sample) => sample.label === "scam" && sample.scamType === scamType);
  const detectionRecall = divide(
    typeSamples.filter((sample) => sample.score >= threshold).length,
    typeSamples.length,
  );
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  return {
    samples: typeSamples.length,
    detectionRecall,
    classificationPrecision: precision,
    classificationRecall: recall,
    classificationFalsePositiveRate: divide(fp, fp + tn),
  };
}

function percent(value: number | null) {
  return value === null ? "N/A" : `${(value * 100).toFixed(2)}%`;
}

function isHashHoldout(id: string) {
  const bucket = Number.parseInt(createHash("sha256").update(id).digest("hex").slice(0, 8), 16) % 5;
  return bucket === 0;
}

function isHoldout(sample: EvaluationSample) {
  if (sample.evaluationSplit) return sample.evaluationSplit === "holdout";
  return isHashHoldout(sample.id);
}

function tableMetrics(entries: Array<[string, Metrics]>) {
  const lines = [
    "| Group | N | Scam | Legit | Precision | Recall | FPR | F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|",
  ];
  for (const [name, metrics] of entries) {
    lines.push(
      `| ${name} | ${metrics.samples} | ${metrics.positive} | ${metrics.negative} | `
      + `${percent(metrics.precision)} | ${percent(metrics.recall)} | `
      + `${percent(metrics.falsePositiveRate)} | ${percent(metrics.f1)} |`,
    );
  }
  return lines.join("\n");
}

const rawDataset = await readFile(datasetPath, "utf8");
const samples = rawDataset
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as EvaluationSample);

const scored: ScoredSample[] = samples.map((sample) => {
  const result = messageAnalysis(sample.text, extractUrls(sample.text));
  return {
    ...sample,
    score: result.score,
    predictedScamType: result.scamType,
    detectedLanguage: result.detectedLanguage,
  };
});

const overall = binaryMetrics(scored, alertThreshold);
const byLanguage = [...new Set(scored.map((sample) => sample.language))]
  .sort()
  .map((language) => [
    language,
    binaryMetrics(scored.filter((sample) => sample.language === language), alertThreshold),
  ] as [string, Metrics]);
const bySource = [...new Set(scored.map((sample) => sample.source))]
  .sort()
  .map((source) => [
    source,
    binaryMetrics(scored.filter((sample) => sample.source === source), alertThreshold),
  ] as [string, Metrics]);
const byType = [...new Set(
  scored.filter((sample) => sample.scamType).map((sample) => sample.scamType as string),
)].sort().map((scamType) => [scamType, categoryMetrics(scored, scamType, alertThreshold)] as const);

const calibrationSamples = scored.filter((sample) => !isHoldout(sample));
const holdoutSamples = scored.filter((sample) => isHoldout(sample));
const securityFocusedSamples = scored.filter((sample) =>
  sample.label === "legitimate" || sample.scamType !== "Generic SMS spam"
);
const authorityReferenceSamples = scored.filter((sample) =>
  sample.source.startsWith("authority-")
);
const securityFocused = binaryMetrics(securityFocusedSamples, alertThreshold);
const authorityReference = binaryMetrics(authorityReferenceSamples, alertThreshold);
const thresholdSweep = Array.from({ length: 96 }, (_, index) => {
  const threshold = index + 1;
  return { threshold, ...binaryMetrics(calibrationSamples, threshold) };
});
const bestF1 = [...thresholdSweep].sort((a, b) =>
  (b.f1 ?? -1) - (a.f1 ?? -1)
  || (a.falsePositiveRate ?? 1) - (b.falsePositiveRate ?? 1)
  || a.threshold - b.threshold
)[0];
const bestUnderFivePercentFpr = thresholdSweep
  .filter((entry) => entry.falsePositiveRate !== null && entry.falsePositiveRate <= 0.05)
  .sort((a, b) =>
    (b.recall ?? -1) - (a.recall ?? -1)
    || (b.precision ?? -1) - (a.precision ?? -1)
    || a.threshold - b.threshold
)[0] ?? null;
const recommendedThreshold = bestUnderFivePercentFpr?.threshold ?? bestF1.threshold;
const holdoutAtRecommendedThreshold = binaryMetrics(holdoutSamples, recommendedThreshold);

const falsePositives = scored
  .filter((sample) => sample.label === "legitimate" && sample.score >= alertThreshold)
  .sort((a, b) => b.score - a.score);
const falseNegatives = scored
  .filter((sample) => sample.label === "scam" && sample.score < alertThreshold)
  .sort((a, b) => a.score - b.score);

const typeLines = [
  "| Scam type | N | Detection recall | Type precision | Type recall | Type FPR |",
  "|---|---:|---:|---:|---:|---:|",
  ...byType.map(([name, metrics]) =>
    `| ${name} | ${metrics.samples} | ${percent(metrics.detectionRecall)} | `
    + `${percent(metrics.classificationPrecision)} | ${percent(metrics.classificationRecall)} | `
    + `${percent(metrics.classificationFalsePositiveRate)} |`
  ),
];

const report = `# ScamShield scoring baseline

Generated: ${new Date().toISOString()}

This report evaluates the local message scoring rules only. A score of ${alertThreshold} or more is treated as an alert
(Medium or High risk). URL reputation providers and deep-scan network checks are deliberately excluded so the run is
deterministic and does not transmit dataset URLs.

## Overall

${tableMetrics([["All samples", overall]])}

## Security-focused view

This view excludes positive samples labelled only as generic advertising spam. Legitimate negatives remain included,
so precision and false-positive rate are not made easier.

The authority-sourced reference set is a development regression set, not an independent performance estimate.

${tableMetrics([
  ["Security scams + all legitimate samples", securityFocused],
  ["Authority-sourced reference set", authorityReference],
])}

## By language

${tableMetrics(byLanguage)}

## By source

${tableMetrics(bySource)}

## By scam type

"Detection recall" asks whether the sample raised any alert. The three "Type" columns are stricter one-vs-rest
classification metrics and require ScamShield to also name the exact annotated category.

${typeLines.join("\n")}

## Threshold calibration

- Current alert threshold ${alertThreshold}: recall ${percent(overall.recall)}, precision ${percent(overall.precision)}, FPR ${percent(overall.falsePositiveRate)}.
- Internal calibration/hashed split: ${calibrationSamples.length}/${holdoutSamples.length}. Authority examples remain
  calibration-only; public corpora use a deterministic sample-ID split.
- Best calibration F1: threshold ${bestF1.threshold} (F1 ${percent(bestF1.f1)}, recall ${percent(bestF1.recall)}, FPR ${percent(bestF1.falsePositiveRate)}).
${bestUnderFivePercentFpr
  ? `- Highest calibration recall with FPR <= 5%: threshold ${bestUnderFivePercentFpr.threshold} (recall ${percent(bestUnderFivePercentFpr.recall)}, precision ${percent(bestUnderFivePercentFpr.precision)}, FPR ${percent(bestUnderFivePercentFpr.falsePositiveRate)}).`
  : "- No tested threshold achieved FPR <= 5%."}
- Internal hashed subset at candidate threshold ${recommendedThreshold}: recall ${percent(holdoutAtRecommendedThreshold.recall)}, precision ${percent(holdoutAtRecommendedThreshold.precision)}, FPR ${percent(holdoutAtRecommendedThreshold.falsePositiveRate)}, F1 ${percent(holdoutAtRecommendedThreshold.f1)}.

This internal report has influenced rule development and must not be presented as independent performance. Use
\`FINAL_HOLDOUT.md\` for the post-model independent estimate. Do not change the production threshold from this report
alone. UCI spam is broader than fraud/scam, while the user collection is user-reported rather than independently
adjudicated.

## Errors to review

- False positives: ${falsePositives.length}. Highest-scoring IDs: ${falsePositives.slice(0, 20).map((sample) => `${sample.id} (${sample.score})`).join(", ") || "none"}.
- False negatives: ${falseNegatives.length}. Lowest-scoring IDs: ${falseNegatives.slice(0, 20).map((sample) => `${sample.id} (${sample.score})`).join(", ") || "none"}.

Raw messages and per-sample results are git-ignored because they may contain user-reported or copyrighted content.
`;

const result = {
  generatedAt: new Date().toISOString(),
  alertThreshold,
  overall,
  securityFocused,
  authorityReference,
  byLanguage: Object.fromEntries(byLanguage),
  bySource: Object.fromEntries(bySource),
  byType: Object.fromEntries(byType),
  calibration: {
    calibrationSamples: calibrationSamples.length,
    holdoutSamples: holdoutSamples.length,
    bestF1,
    bestUnderFivePercentFpr,
    recommendedThreshold,
    holdoutAtRecommendedThreshold,
  },
  errors: {
    falsePositives: falsePositives.map(({ id, source, score, predictedScamType }) => ({ id, source, score, predictedScamType })),
    falseNegatives: falseNegatives.map(({ id, source, score, scamType, predictedScamType }) => ({ id, source, score, scamType, predictedScamType })),
  },
};

await mkdir(resultsDir, { recursive: true });
await writeFile(path.join(resultsDir, "metrics.json"), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(path.join(resultsDir, "report.md"), report);
await writeFile(path.join(evaluationDir, "BASELINE.md"), report);
console.log(report);
