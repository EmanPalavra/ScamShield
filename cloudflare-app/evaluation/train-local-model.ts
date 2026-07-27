import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageRuleAnalysis } from "../worker/scanner/message-analysis.ts";
import { extractMlFeatures, ML_FEATURE_DIMENSION } from "../worker/scanner/ml-features.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const projectDir = path.dirname(evaluationDir);
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const imcPath = path.join(evaluationDir, "data", "raw", "imc25-smishing.csv");
const smishxPath = path.join(evaluationDir, "data", "raw", "smishx-holdout.csv");
const modelPath = path.join(projectDir, "worker", "scanner", "ml-model.ts");
const reportPath = path.join(evaluationDir, "MODEL_TRAINING.md");
const epochs = 3;
const learningRate = 0.7;
const biasLearningRate = 0.08;
const l2 = 0.00002;

interface TrainingSample {
  id: string;
  text: string;
  label: 0 | 1;
  source: string;
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

function normalizeText(text: string) {
  return text.normalize("NFKC").toLocaleLowerCase().replace(/\s+/g, " ").trim();
}

function stableHash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function sigmoid(value: number) {
  if (value >= 0) return 1 / (1 + Math.exp(-value));
  const exp = Math.exp(value);
  return exp / (1 + exp);
}

function probability(weights: Float64Array, bias: number, text: string) {
  let value = bias;
  for (const [index, feature] of extractMlFeatures(text)) value += weights[index] * feature;
  return sigmoid(value);
}

const samples: TrainingSample[] = [];
const generated = (await readFile(generatedPath, "utf8"))
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as {
    id: string;
    text: string;
    label: "scam" | "legitimate";
    scamType: string | null;
    source: string;
  });
for (const row of generated) {
  if (row.label === "scam" && row.scamType === "Generic SMS spam") continue;
  samples.push({
    id: `existing:${row.id}`,
    text: row.text,
    label: row.label === "scam" ? 1 : 0,
    source: row.source,
  });
}

const securityTypes = new Set(["banking", "delivery", "government", "telecom", "hey mum/dad", "others"]);
for (const [index, row] of records(await readFile(imcPath, "utf8")).entries()) {
  if (!row.text || !securityTypes.has(row.scam_type.toLocaleLowerCase())) continue;
  samples.push({ id: `imc:${index}`, text: row.text, label: 1, source: "imc25-smishing" });
}
for (const [index, row] of records(await readFile(smishxPath, "utf8")).entries()) {
  if (!row.SMS || !["smishing", "legitimate"].includes(row.label)) continue;
  samples.push({
    id: `smishx:${index}`,
    text: row.SMS,
    label: row.label === "smishing" ? 1 : 0,
    source: "smishx",
  });
}

const unique = new Map<string, TrainingSample>();
const conflicts = new Set<string>();
for (const sample of samples) {
  const key = stableHash(normalizeText(sample.text));
  const existing = unique.get(key);
  if (existing && existing.label !== sample.label) {
    unique.delete(key);
    conflicts.add(key);
  } else if (!conflicts.has(key) && !existing) {
    unique.set(key, sample);
  }
}
const deduplicated = [...unique.values()];
const validation = deduplicated.filter((sample) =>
  Number.parseInt(stableHash(`validation:${normalizeText(sample.text)}`).slice(0, 8), 16) % 5 === 0
);
const validationIds = new Set(validation.map((sample) => sample.id));
const training = deduplicated.filter((sample) => !validationIds.has(sample.id));

const positives = training.filter((sample) => sample.label === 1).length;
const negatives = training.length - positives;
const positiveWeight = training.length / (2 * positives);
const negativeWeight = training.length / (2 * negatives);
const weights = new Float64Array(ML_FEATURE_DIMENSION);
const gradientSquares = new Float64Array(ML_FEATURE_DIMENSION);
let bias = 0;
let biasGradientSquare = 0;

for (let epoch = 0; epoch < epochs; epoch += 1) {
  const ordered = [...training].sort((left, right) =>
    stableHash(`${epoch}:${left.id}`).localeCompare(stableHash(`${epoch}:${right.id}`))
  );
  let loss = 0;
  for (const sample of ordered) {
    const features = extractMlFeatures(sample.text);
    let logit = bias;
    for (const [index, value] of features) logit += weights[index] * value;
    const predicted = sigmoid(logit);
    const classWeight = sample.label ? positiveWeight : negativeWeight;
    const error = (predicted - sample.label) * classWeight;
    loss += -classWeight * (
      sample.label * Math.log(Math.max(predicted, 1e-9))
      + (1 - sample.label) * Math.log(Math.max(1 - predicted, 1e-9))
    );
    biasGradientSquare += error * error;
    bias -= (biasLearningRate * error) / Math.sqrt(biasGradientSquare + 1e-8);
    for (const [index, value] of features) {
      const gradient = error * value + l2 * weights[index];
      gradientSquares[index] += gradient * gradient;
      weights[index] -= (learningRate * gradient) / Math.sqrt(gradientSquares[index] + 1e-8);
    }
  }
  console.log(`Epoch ${epoch + 1}/${epochs}: weighted log loss ${(loss / ordered.length).toFixed(4)}`);
}

let maxWeight = 0;
for (const weight of weights) maxWeight = Math.max(maxWeight, Math.abs(weight));
const weightScale = maxWeight / 127 || 1;
const quantized = new Int8Array(ML_FEATURE_DIMENSION);
const quantizedWeights = new Float64Array(ML_FEATURE_DIMENSION);
for (let index = 0; index < weights.length; index += 1) {
  quantized[index] = Math.max(-127, Math.min(127, Math.round(weights[index] / weightScale)));
  quantizedWeights[index] = quantized[index] * weightScale;
}

const validationPredictions = validation.map((sample) => ({
  label: sample.label,
  ml: probability(quantizedWeights, bias, sample.text),
  analysis: messageRuleAnalysis(sample.text, extractUrls(sample.text)),
}));

function metrics(decisionThreshold: number) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const row of validationPredictions) {
    const predicted = row.analysis.score >= 34 || (
      !row.analysis.context.routineAccountNotice
      && row.ml >= decisionThreshold
    );
    if (row.label && predicted) tp += 1;
    else if (row.label) fn += 1;
    else if (predicted) fp += 1;
    else tn += 1;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { tp, fp, tn, fn, precision, recall, fpr: fp / Math.max(1, fp + tn), f1 };
}

const ruleOnly = metrics(1);
const maximumFpr = Math.max(0.03, ruleOnly.fpr + 0.005);
const candidates: Array<{
  decisionThreshold: number;
  result: ReturnType<typeof metrics>;
}> = [];
// Quantized n-gram models can be overconfident on unfamiliar wording. Requiring
// at least 99.5% keeps ML as a conservative gap-filler instead of a primary veto.
for (let thresholdStep = 995; thresholdStep <= 999; thresholdStep += 1) {
  const decisionThreshold = thresholdStep / 1_000;
  const result = metrics(decisionThreshold);
  if (result.fpr <= maximumFpr) candidates.push({ decisionThreshold, result });
}
const best = candidates.sort((left, right) =>
  right.result.f1 - left.result.f1
  || right.result.recall - left.result.recall
  || left.result.fpr - right.result.fpr
)[0];
if (!best) throw new Error("No hybrid model candidate met the validation FPR guardrail.");

const encodedBytes = Buffer.alloc(quantized.length);
for (let index = 0; index < quantized.length; index += 1) encodedBytes[index] = quantized[index] + 128;
const weightsBase64 = encodedBytes.toString("base64");
const fingerprint = stableHash(JSON.stringify({
  samples: deduplicated.map((sample) => stableHash(`${sample.label}:${normalizeText(sample.text)}`)).sort(),
  epochs,
  learningRate,
  l2,
})).slice(0, 16);

const modelSource = `// Generated deterministically by evaluation/train-local-model.ts.
export const mlModel = {
  version: "local-logreg-${fingerprint}",
  dimension: ${ML_FEATURE_DIMENSION},
  weightScale: ${weightScale},
  weightsBase64: "${weightsBase64}",
  bias: ${bias},
  decisionThreshold: ${best.decisionThreshold},
} as const;
`;
await writeFile(modelPath, modelSource);

const bySource = Object.fromEntries(
  [...new Set(deduplicated.map((sample) => sample.source))].sort().map((source) => [
    source,
    deduplicated.filter((sample) => sample.source === source).length,
  ]),
);
const report = `# Local ML model training

Generated: ${new Date().toISOString()}
Model: local-logreg-${fingerprint}

- Algorithm: quantized feature-hashed logistic regression with AdaGrad.
- Features: normalized character 3/4-grams, word unigrams/bigrams, and bounded structural indicators.
- Training/validation: ${training.length}/${validation.length}, deterministic 80/20 text-hash split after exact deduplication.
- Training positives/negatives: ${positives}/${negatives}.
- Label conflicts excluded: ${conflicts.size}.
- Model size: ${quantized.byteLength.toLocaleString()} weight bytes before Base64.
- Hybrid policy: preserve every rule alert; ML may only raise a Low result to Medium.
- False-positive guardrail: no more than 0.50 percentage points above rules-only validation FPR (or 3.00% total, whichever is higher).
- Decision threshold: ${best.decisionThreshold.toFixed(3)}.

## Internal validation

| Method | N | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules only | ${validation.length} | ${ruleOnly.tp} | ${ruleOnly.fp} | ${ruleOnly.tn} | ${ruleOnly.fn} | ${(ruleOnly.precision * 100).toFixed(2)}% | ${(ruleOnly.recall * 100).toFixed(2)}% | ${(ruleOnly.fpr * 100).toFixed(2)}% | ${(ruleOnly.f1 * 100).toFixed(2)}% |
| Hybrid | ${validation.length} | ${best.result.tp} | ${best.result.fp} | ${best.result.tn} | ${best.result.fn} | ${(best.result.precision * 100).toFixed(2)}% | ${(best.result.recall * 100).toFixed(2)}% | ${(best.result.fpr * 100).toFixed(2)}% | ${(best.result.f1 * 100).toFixed(2)}% |

This is a calibration result, not an independent product-performance claim.

## Source counts

\`\`\`json
${JSON.stringify(bySource, null, 2)}
\`\`\`
`;
await writeFile(reportPath, report);
console.log(report);
