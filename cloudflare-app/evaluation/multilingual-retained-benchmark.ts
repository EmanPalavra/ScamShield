import { createHash } from "node:crypto";
import type { EvaluationSample } from "./dataset-types.ts";

export const retainedLanguages = ["English", "German", "French", "Dutch", "Spanish", "BHS"] as const;
export type RetainedLanguage = typeof retainedLanguages[number];

export interface RetainedSample {
  id: string;
  text: string;
  label: 0 | 1;
  language: RetainedLanguage;
}

const languageAliases: Record<RetainedLanguage, string[]> = {
  English: ["English"],
  German: ["German"],
  French: ["French"],
  Dutch: ["Dutch"],
  Spanish: ["Spanish"],
  BHS: ["Croatian", "Serbian"],
};
const securityTypes = new Set(["banking", "delivery", "government", "telecom", "hey mum/dad", "others"]);

export function parseCsv(text: string) {
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

export function benchmarkTemplate(text: string) {
  return text
    .normalize("NFKC")
    .toLocaleLowerCase()
    .replace(/<[^>]+>/g, "<slot>")
    .replace(/(?:https?:\/\/|www\.)\S+|\b\S+\.[a-z]{2,}(?:\/\S*)?/gi, "<url>")
    .replace(/\b\d+(?:[.,]\d+)?\b/g, "<number>")
    .replace(/\s+/g, " ")
    .trim();
}

function stableHash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function takeTemplateGroups(samples: RetainedSample[], maximum: number) {
  const groups = new Map<string, RetainedSample[]>();
  for (const sample of samples) {
    const template = benchmarkTemplate(sample.text);
    const group = groups.get(template) ?? [];
    group.push(sample);
    groups.set(template, group);
  }
  const selected: RetainedSample[] = [];
  for (const [, group] of [...groups].sort(([left], [right]) =>
    stableHash(`retained-v1:${left}`).localeCompare(stableHash(`retained-v1:${right}`))
  )) {
    if (selected.length && selected.length + group.length > maximum) continue;
    selected.push(...group);
    if (selected.length >= maximum) break;
  }
  return selected;
}

export function selectRetainedBenchmark(imcCsv: string, generated: EvaluationSample[]) {
  const rows = parseCsv(imcCsv.replace(/^\uFEFF/, ""));
  const headers = rows.shift() ?? [];
  const columns = Object.fromEntries(headers.map((header, index) => [header, index]));
  const result: RetainedSample[] = [];

  for (const language of retainedLanguages) {
    const positiveCandidates = rows.flatMap((row, index) => {
      const text = row[columns.text]?.trim();
      const sourceLanguage = row[columns.language]?.trim();
      const scamType = row[columns.scam_type]?.trim().toLocaleLowerCase();
      if (
        !text
        || !languageAliases[language].includes(sourceLanguage)
        || !securityTypes.has(scamType)
      ) return [];
      return [{
        id: `imc:${index}`,
        text,
        label: 1 as const,
        language,
      }];
    });
    const maximum = language === "BHS" ? positiveCandidates.length : 400;
    const positives = takeTemplateGroups(positiveCandidates, maximum);
    const negativeCandidates = generated.flatMap((sample) => {
      const matches = language === "BHS"
        ? sample.language === "Bosnian / Croatian / Serbian"
        : sample.language === language;
      if (sample.label !== "legitimate" || !matches) return [];
      return [{
        id: `existing:${sample.id}`,
        text: sample.text,
        label: 0 as const,
        language,
      }];
    });
    const negatives = takeTemplateGroups(negativeCandidates, positives.length);
    result.push(...positives, ...negatives);
  }
  return result;
}

export function retainedFingerprint(samples: RetainedSample[]) {
  return stableHash(samples
    .map((sample) => `${sample.id}:${sample.label}:${stableHash(benchmarkTemplate(sample.text))}`)
    .sort()
    .join("\n"));
}
