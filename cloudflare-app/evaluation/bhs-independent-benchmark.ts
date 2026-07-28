import { createHash } from "node:crypto";
import {
  bhsCurrentRealWorldRecords,
  type BhsCountry,
} from "./bhs-current-real-world.ts";
import { bhsIndependentChallengeSamples } from "./bhs-independent-scam-benchmark.ts";
import type { EvaluationSample } from "./dataset-types.ts";
import { selectLanguageHoldoutNegatives } from "./language-holdout-split.ts";

export type BhsBenchmarkProvenance =
  | "authority-verbatim-redacted"
  | "authority-described"
  | "source-grounded-synthetic"
  | "authentic-legitimate";

export interface BhsBenchmarkSample {
  id: string;
  label: "scam" | "legitimate";
  text: string;
  country: BhsCountry | "BA-corpus";
  provenance: BhsBenchmarkProvenance;
  family: string;
  sourceUrl: string | null;
}

export function selectBhsIndependentBenchmark(generated: EvaluationSample[]) {
  const legitimate = selectLanguageHoldoutNegatives(generated).get("BHS") ?? [];
  if (legitimate.length < 500) {
    throw new Error(`BHS benchmark needs at least 500 legitimate messages, found ${legitimate.length}.`);
  }

  const realScams: BhsBenchmarkSample[] = bhsCurrentRealWorldRecords.map((record) => ({
    id: `real:${record.id}`,
    label: "scam",
    text: record.text,
    country: record.country,
    provenance: record.evidenceKind === "verbatim-redacted"
      ? "authority-verbatim-redacted"
      : "authority-described",
    family: record.scamType,
    sourceUrl: record.sourceUrl,
  }));
  const challengeScams: BhsBenchmarkSample[] = bhsIndependentChallengeSamples.map((sample) => ({
    id: `challenge:${sample.id}`,
    label: "scam",
    text: sample.text,
    country: sample.country,
    provenance: sample.provenance,
    family: sample.family,
    sourceUrl: sample.sourceUrl,
  }));
  const legitimateSamples: BhsBenchmarkSample[] = legitimate.map((sample) => ({
    id: `legitimate:${sample.id}`,
    label: "legitimate",
    text: sample.text,
    country: "BA-corpus",
    provenance: "authentic-legitimate",
    family: "ordinary-sms",
    sourceUrl: sample.sourceUrl,
  }));

  return [...realScams, ...challengeScams, ...legitimateSamples];
}

export function bhsBenchmarkFingerprint(samples: BhsBenchmarkSample[]) {
  const canonical = [...samples]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(({ id, label, text, country, provenance, family }) => ({
      id,
      label,
      text: text.normalize("NFKC").replace(/\s+/g, " ").trim(),
      country,
      provenance,
      family,
    }));
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}
