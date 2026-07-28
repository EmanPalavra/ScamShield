import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { extractUrls, messageAnalysis } from "../worker/scanner/message-analysis.ts";
import { mlModel } from "../worker/scanner/ml-model.ts";
import {
  bhsCurrentRealWorldRecords,
  type BhsCountry,
} from "./bhs-current-real-world.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const resultsDir = path.join(evaluationDir, "results");

function recall(country: BhsCountry, split: "calibration" | "holdout") {
  const rows = bhsCurrentRealWorldRecords.filter((row) =>
    row.country === country && row.evaluationSplit === split
  );
  const detected = rows.filter((row) =>
    messageAnalysis(row.text, extractUrls(row.text)).score >= 34
  ).length;
  return {
    samples: rows.length,
    detected,
    recall: rows.length ? detected / rows.length : null,
  };
}

const countries: BhsCountry[] = ["BA", "HR", "RS"];
const result = {
  generatedAt: new Date().toISOString(),
  modelVersion: mlModel.version,
  threshold: 34,
  records: bhsCurrentRealWorldRecords.length,
  evidence: {
    verbatimRedacted: bhsCurrentRealWorldRecords.filter((row) =>
      row.evidenceKind === "verbatim-redacted"
    ).length,
    authorityDescribed: bhsCurrentRealWorldRecords.filter((row) =>
      row.evidenceKind === "authority-described"
    ).length,
  },
  calibration: Object.fromEntries(countries.map((country) => [country, recall(country, "calibration")])),
  sourceHeldOut: Object.fromEntries(countries.map((country) => [country, recall(country, "holdout")])),
  caveat: "This authority-confirmed set contains scam positives only. It measures recall, not precision, false-positive rate, or F1.",
};

await mkdir(resultsDir, { recursive: true });
await writeFile(
  path.join(resultsDir, "bhs-current-real-world.json"),
  `${JSON.stringify(result, null, 2)}\n`,
);
console.log(JSON.stringify(result, null, 2));
