import { createHash } from "node:crypto";
import type { EvaluationSample } from "./dataset-types.ts";

export const benchmarkLanguages = ["English", "German", "French", "Dutch", "BHS"] as const;
export type BenchmarkLanguage = typeof benchmarkLanguages[number];

const reservedNegativesPerLanguage: Record<BenchmarkLanguage, number> = {
  English: 400,
  German: 400,
  French: 400,
  Dutch: 400,
  BHS: 600,
};

export function benchmarkLanguage(language: string): BenchmarkLanguage | null {
  if (language === "English") return "English";
  if (language === "German") return "German";
  if (language === "French") return "French";
  if (language === "Dutch") return "Dutch";
  if (language === "Bosnian / Croatian / Serbian") return "BHS";
  return null;
}

export function normalizeBenchmarkText(text: string) {
  return text
    .normalize("NFKC")
    .toLocaleLowerCase()
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function benchmarkHash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

export function benchmarkTemplate(text: string) {
  return normalizeBenchmarkText(text)
    .replace(/(?:https?:\/\/|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/\S*)?/giu, " <url> ")
    .replace(/\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/giu, " <email> ")
    .replace(/\b(?:\+?\d[\d\s()./-]{5,}\d)\b/gu, " <number> ")
    .replace(/\b\d+(?:[.,]\d+)?\b/gu, " <number> ")
    .replace(/\[(?:anonymized|redacted)\]/giu, " <private> ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Reserve complete normalized-template groups before training. This prevents a
 * templated sibling of a benchmark negative from remaining in model training.
 */
export function selectLanguageHoldoutNegatives(samples: EvaluationSample[]) {
  const selected = new Map<BenchmarkLanguage, EvaluationSample[]>(
    benchmarkLanguages.map((language) => [language, []]),
  );

  for (const language of benchmarkLanguages) {
    const groups = new Map<string, EvaluationSample[]>();
    for (const sample of samples) {
      if (sample.label !== "legitimate" || benchmarkLanguage(sample.language) !== language) continue;
      const key = benchmarkHash(benchmarkTemplate(sample.text));
      const group = groups.get(key) ?? [];
      group.push(sample);
      groups.set(key, group);
    }

    const orderedGroups = [...groups.entries()]
      .sort(([left], [right]) => left.localeCompare(right));
    const languageSelection: EvaluationSample[] = [];
    for (const [, group] of orderedGroups) {
      if (languageSelection.length >= reservedNegativesPerLanguage[language]) break;
      languageSelection.push(...group);
    }
    selected.set(language, languageSelection);
  }

  return selected;
}

export function languageHoldoutNegativeIds(samples: EvaluationSample[]) {
  return new Set(
    [...selectLanguageHoldoutNegatives(samples).values()]
      .flat()
      .map((sample) => sample.id),
  );
}
