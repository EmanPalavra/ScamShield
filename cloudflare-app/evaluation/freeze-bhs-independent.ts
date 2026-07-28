import { createHash } from "node:crypto";
import { access, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  bhsBenchmarkFingerprint,
  selectBhsIndependentBenchmark,
} from "./bhs-independent-benchmark.ts";
import type { EvaluationSample } from "./dataset-types.ts";
import { mlModel } from "../worker/scanner/ml-model.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const generatedPath = path.join(evaluationDir, "data", "generated", "messages.jsonl");
const manifestPath = path.join(evaluationDir, "bhs-independent-manifest.json");
try {
  await access(manifestPath);
  throw new Error("BHS independent benchmark is already frozen. Delete it only when intentionally creating a new benchmark version.");
} catch (error) {
  if (error instanceof Error && !("code" in error && error.code === "ENOENT")) throw error;
}
const raw = await readFile(generatedPath, "utf8");
const generated = raw
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line) as EvaluationSample);
const samples = selectBhsIndependentBenchmark(generated);
const counts = Object.fromEntries(
  [...new Set(samples.map((sample) => sample.provenance))].map((provenance) => [
    provenance,
    samples.filter((sample) => sample.provenance === provenance).length,
  ]),
);

const manifest = {
  status: "frozen-unscored",
  frozenAt: new Date().toISOString(),
  frozenBeforeModel: mlModel.version,
  generatedDatasetSha256: createHash("sha256").update(raw).digest("hex"),
  fingerprint: bhsBenchmarkFingerprint(samples),
  total: samples.length,
  scam: samples.filter((sample) => sample.label === "scam").length,
  legitimate: samples.filter((sample) => sample.label === "legitimate").length,
  counts,
  policy: "The benchmark must not be used to change rules, features, labels, thresholds, or training data after its first score. Any such change retires this manifest.",
  limitations: [
    "Only authority-verbatim rows are direct transcriptions of observed scam messages.",
    "Authority-described rows summarize campaigns explicitly reported by the cited institution.",
    "The 75 source-grounded challenge rows are synthetic and are reported separately from real-world rows.",
    "Some real campaign families influenced rules before this formal freeze; the report must not call the real-world tier fully untouched.",
    "Legitimate controls are authentic Bosnian SMS messages from the Sarajevo Corpus and are excluded from model training by complete normalized-template group.",
  ],
};

await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest, null, 2));
