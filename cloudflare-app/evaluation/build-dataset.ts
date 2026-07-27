import { createHash } from "node:crypto";
import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { unzipSync } from "fflate";
import { authorityScamExamples } from "./authority-scam-examples.ts";
import { authorityScamCampaigns } from "./authority-scam-campaigns.ts";
import { authorityScamAudit } from "./authority-scam-audit.ts";
import type { EvaluationSample } from "./dataset-types.ts";
import { userScamTypes } from "./user-scam-labels.ts";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.dirname(evaluationDir);
const repositoryDir = path.dirname(appDir);
const rawDir = path.join(evaluationDir, "data", "raw");
const generatedDir = path.join(evaluationDir, "data", "generated");

function stableId(prefix: string, text: string) {
  return `${prefix}-${createHash("sha256").update(text).digest("hex").slice(0, 16)}`;
}

function removeOuterQuotes(text: string) {
  const trimmed = text.trim();
  return trimmed.startsWith("\"") && trimmed.endsWith("\"")
    ? trimmed.slice(1, -1).trim()
    : trimmed;
}

function parseUserScams(text: string): EvaluationSample[] {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  const entries: Array<{ number: number; lines: string[] }> = [];
  let expected = 1;
  let current: { number: number; lines: string[] } | null = null;

  for (const line of lines) {
    const marker = line.match(/^\s*(\d{1,2})(?:\.\s*|\s*$)(.*)$/);
    if (marker && Number(marker[1]) === expected && expected <= userScamTypes.length) {
      if (current) entries.push(current);
      current = { number: expected, lines: marker[2] ? [marker[2]] : [] };
      expected += 1;
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) entries.push(current);

  if (entries.length !== userScamTypes.length) {
    throw new Error(`Expected ${userScamTypes.length} user scams, parsed ${entries.length}.`);
  }

  return entries.map((entry) => {
    const message = removeOuterQuotes(entry.lines.join("\n"));
    return {
      id: `user-scams-${String(entry.number).padStart(3, "0")}`,
      label: "scam",
      language: "English",
      scamType: userScamTypes[entry.number - 1],
      text: message,
      source: "user-scams",
      sourceUrl: null,
      annotationStatus: "user-reported",
    };
  });
}

function parseUci(text: string): EvaluationSample[] {
  return text
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      const tab = line.indexOf("\t");
      if (tab < 0) throw new Error(`Malformed UCI row ${index + 1}.`);
      const corpusLabel = line.slice(0, tab);
      const message = line.slice(tab + 1).trim();
      if (corpusLabel !== "ham" && corpusLabel !== "spam") {
        throw new Error(`Unknown UCI label "${corpusLabel}" on row ${index + 1}.`);
      }
      return {
        id: stableId("uci-sms", `${corpusLabel}\0${message}`),
        label: corpusLabel === "spam" ? "scam" : "legitimate",
        language: "English",
        scamType: corpusLabel === "spam" ? "Generic SMS spam" : null,
        text: message,
        source: "uci-sms-spam",
        sourceUrl: "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
        annotationStatus: "public-corpus-label",
      };
    });
}

function parseDelimited(text: string, separator = ";") {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === "\"") {
      if (quoted && text[index + 1] === "\"") {
        field += "\"";
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (character === separator && !quoted) {
      row.push(field);
      field = "";
    } else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(field);
      if (row.some((value) => value.length)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function decodeXml(text: string) {
  const namedEntities: Record<string, string> = {
    amp: "&",
    apos: "'",
    gt: ">",
    lt: "<",
    quot: "\"",
  };
  return text
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal: string) => String.fromCodePoint(Number.parseInt(decimal, 10)))
    .replace(/&([a-z]+);/gi, (entity, name: string) => namedEntities[name] ?? entity);
}

function plainXmlText(text: string) {
  return decodeXml(
    text
      .replace(/<fs\b[\s\S]*?<\/fs>/gi, " [anonymized] ")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/\s+/g, " ")
    .trim();
}

function deterministicLimit(samples: EvaluationSample[], maximum: number) {
  if (samples.length <= maximum) return samples;
  return samples
    .map((sample) => ({
      sample,
      order: createHash("sha256").update(sample.id).digest("hex"),
    }))
    .sort((a, b) => a.order.localeCompare(b.order))
    .slice(0, maximum)
    .map(({ sample }) => sample);
}

function parseEnglishSmishing(text: string): EvaluationSample[] {
  const rows = parseDelimited(text.replace(/^\uFEFF/, ""), ",");
  const headers = rows.shift()?.map((header) => header.trim().toLowerCase()) ?? [];
  const labelIndex = headers.indexOf("label");
  const textIndex = headers.indexOf("text");
  if (labelIndex < 0 || textIndex < 0) {
    throw new Error(`English smishing CSV needs LABEL and TEXT columns. Found: ${headers.join(", ")}`);
  }
  return rows.flatMap((row) => {
    const label = row[labelIndex]?.trim().toLowerCase();
    const message = row[textIndex]?.trim();
    if (!message || !["ham", "spam", "smishing"].includes(label)) return [];
    const isScam = label !== "ham";
    return [{
      id: stableId("english-smishing", `${label}\0${message}`),
      label: isScam ? "scam" : "legitimate",
      language: "English",
      scamType: label === "smishing" ? "Account takeover / phishing" : label === "spam" ? "Generic SMS spam" : null,
      text: message,
      source: "english-smishing-5971",
      sourceUrl: "https://data.mendeley.com/datasets/f45bkkt8pr/1",
      annotationStatus: "public-corpus-label",
    }];
  });
}

function parseSarajevoSms(archive: Uint8Array): EvaluationSample[] {
  const files = unzipSync(archive);
  const messages: EvaluationSample[] = [];
  for (const [filename, content] of Object.entries(files)) {
    if (!filename.endsWith(".conllu")) continue;
    const text = new TextDecoder().decode(content);
    for (const document of text.split(/(?=^#\s*newdoc id\s*=)/gm)) {
      const corpusId = document.match(/^#\s*newdoc id\s*=\s*(.+)$/m)?.[1].trim();
      const message = [...document.matchAll(/^#\s*text\s*=\s*(.+)$/gm)]
        .map((match) => match[1].trim())
        .filter(Boolean)
        .join(" ");
      if (!message) continue;
      messages.push({
        id: corpusId ? `sarajevo-sms-${corpusId}` : stableId("sarajevo-sms", message),
        label: "legitimate",
        language: "Bosnian / Croatian / Serbian",
        scamType: null,
        text: message,
        source: "sarajevo-sms-1.1",
        sourceUrl: "https://www.clarin.si/repository/xmlui/handle/11356/1956",
        annotationStatus: "public-corpus-label",
      });
    }
  }
  if (messages.length !== 10_000) {
    throw new Error(`Expected 10,000 Sarajevo SMS messages, parsed ${messages.length}.`);
  }
  return messages;
}

function parseFrenchSms(text: string): EvaluationSample[] {
  const messages: EvaluationSample[] = [];
  for (const match of text.matchAll(/<post\b([^>]*)type="sms"[^>]*>([\s\S]*?)<\/post>/gi)) {
    const id = match[1].match(/xml:id="([^"]+)"/i)?.[1];
    const paragraph = match[2].match(/<p\b[^>]*>([\s\S]*?)<\/p>/i)?.[1] ?? match[2];
    const message = plainXmlText(paragraph);
    if (!message) continue;
    messages.push({
      id: id ? `french-88milsms-${id}` : stableId("french-88milsms", message),
      label: "legitimate",
      language: "French",
      scamType: null,
      text: message,
      source: "french-88milsms",
      sourceUrl: "https://hdl.handle.net/11403/comere/cmr-88milsms/cmr-88milsms-tei-v1",
      annotationStatus: "public-corpus-label",
    });
  }
  if (messages.length < 88_000) {
    throw new Error(`Expected at least 88,000 French SMS messages, parsed ${messages.length}.`);
  }
  return deterministicLimit(messages, 10_000);
}

function parseGermanChat(archive: Uint8Array): EvaluationSample[] {
  const files = unzipSync(archive);
  const entry = Object.entries(files).find(([filename]) => filename.endsWith(".tei.xml"));
  if (!entry) throw new Error("Dortmund chat archive has no TEI XML file.");
  const xml = new TextDecoder("windows-1252").decode(entry[1]);
  const messages: EvaluationSample[] = [];
  for (const match of xml.matchAll(/<post\b([^>]*)auto="false"[^>]*type="standard"[^>]*>([\s\S]*?)<\/post>/gi)) {
    const id = match[1].match(/xml:id="([^"]+)"/i)?.[1];
    const message = plainXmlText(match[2].replace(/<time\b[\s\S]*?<\/time>/gi, " "));
    if (!message || message.length > 2_000) continue;
    messages.push({
      id: id ? `dortmund-chat-${id}` : stableId("dortmund-chat", message),
      label: "legitimate",
      language: "German",
      scamType: null,
      text: message,
      source: "dortmund-chat-2.0",
      sourceUrl: "https://clarin.bbaw.de/de/objects/dwds%3A10/",
      annotationStatus: "public-corpus-label",
    });
  }
  if (messages.length < 1_000) {
    throw new Error(`Expected at least 1,000 German chat messages, parsed ${messages.length}.`);
  }
  return deterministicLimit(messages, 10_000);
}

function parseDutchWhatsapp(files: Array<{ filename: string; text: string }>): EvaluationSample[] {
  const messages: EvaluationSample[] = [];
  for (const { filename, text } of files) {
    for (const match of text.matchAll(/<event\b([^>]*)class="message"[^>]*>([\s\S]*?)<\/event>/gi)) {
      const id = match[1].match(/xml:id="([^"]+)"/i)?.[1];
      const directText = match[2].match(/^\s*<t\b[^>]*>([\s\S]*?)<\/t>/i)?.[1];
      if (!directText) continue;
      const message = plainXmlText(directText);
      if (!message || message.length > 2_000) continue;
      messages.push({
        id: id ? `dutch-whatsapp-${id}` : stableId(`dutch-whatsapp-${filename}`, message),
        label: "legitimate",
        language: "Dutch",
        scamType: null,
        text: message,
        source: "dutch-whatsapp-berntzen",
        sourceUrl: "https://doi.org/10.17026/DANS-XZZ-UGTW",
        annotationStatus: "public-corpus-label",
      });
    }
  }
  if (messages.length < 500) {
    throw new Error(`Expected at least 500 Dutch WhatsApp messages, parsed ${messages.length}.`);
  }
  return deterministicLimit(messages, 10_000);
}

function parseSpaPhish(text: string): EvaluationSample[] {
  const cleanText = text.replace(/^\uFEFF/, "");
  const headerLine = cleanText.slice(0, cleanText.indexOf("\n"));
  const separator = (headerLine.match(/,/g)?.length ?? 0) > (headerLine.match(/;/g)?.length ?? 0) ? "," : ";";
  const rows = parseDelimited(cleanText, separator);
  const headers = rows.shift()?.map((header) => header.trim().toLowerCase()) ?? [];
  const findColumn = (...names: string[]) => names
    .map((name) => headers.indexOf(name))
    .find((index) => index >= 0) ?? -1;
  const labelIndex = findColumn("label", "class");
  const subjectIndex = findColumn("subject", "subject_text", "asunto");
  const bodyIndex = findColumn("body", "body_text", "message", "text", "cuerpo");
  const hashIndex = findColumn("hash", "sha256", "id");

  if (labelIndex < 0 || bodyIndex < 0) {
    throw new Error(`SpaPhish CSV needs Label and body columns. Found: ${headers.join(", ")}`);
  }

  return rows.flatMap((row, index) => {
    const labelValue = row[labelIndex]?.trim().toLowerCase();
    const isScam = ["1", "phishing", "phish", "scam"].includes(labelValue);
    const isLegitimate = ["0", "legitimate", "legit", "ham"].includes(labelValue);
    if (!isScam && !isLegitimate) return [];
    const subject = subjectIndex >= 0 ? row[subjectIndex]?.trim() : "";
    const body = row[bodyIndex]?.trim() ?? "";
    const message = [subject, body].filter(Boolean).join("\n\n");
    if (!message) return [];
    const suppliedId = hashIndex >= 0 ? row[hashIndex]?.trim() : "";
    return [{
      id: suppliedId ? `spaphish-${suppliedId}` : stableId(`spaphish-${index + 1}`, message),
      label: isScam ? "scam" : "legitimate",
      language: "Spanish",
      scamType: isScam ? "Account takeover / phishing" : null,
      text: message,
      source: "spaphish-v5",
      sourceUrl: "https://data.mendeley.com/datasets/hz2d6gz7pc/5",
      annotationStatus: "expert-reviewed",
    }];
  });
}

async function exists(file: string) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

const samples: EvaluationSample[] = [];
samples.push(...parseUserScams(await readFile(path.join(repositoryDir, "Scams.txt"), "utf8")));
samples.push(...authorityScamExamples);
samples.push(...authorityScamCampaigns);
samples.push(...authorityScamAudit);

const uciPath = path.join(rawDir, "SMSSpamCollection");
if (await exists(uciPath)) samples.push(...parseUci(await readFile(uciPath, "utf8")));
else console.warn("UCI corpus is missing. Run: pnpm run evaluate:download");

const spaPhishPath = path.join(rawDir, "spaphish.csv");
if (await exists(spaPhishPath)) samples.push(...parseSpaPhish(await readFile(spaPhishPath, "utf8")));
else console.warn("SpaPhish CSV is missing; Spanish metrics will not be produced.");

const englishSmishingPath = path.join(rawDir, "english-smishing.csv");
if (await exists(englishSmishingPath)) {
  const content = await readFile(englishSmishingPath, "utf8");
  samples.push(...parseEnglishSmishing(content));
} else {
  console.warn("English smishing corpus is missing; modern English smishing coverage will be reduced.");
}

const sarajevoSmsPath = path.join(rawDir, "sarajevo-sms.zip");
if (await exists(sarajevoSmsPath)) {
  samples.push(...parseSarajevoSms(await readFile(sarajevoSmsPath)));
} else {
  console.warn("Sarajevo SMS corpus is missing; BHS legitimate metrics will not be produced.");
}

const frenchSmsPath = path.join(rawDir, "french-88milsms.xml");
if (await exists(frenchSmsPath)) {
  samples.push(...parseFrenchSms(await readFile(frenchSmsPath, "utf8")));
} else {
  console.warn("88milSMS corpus is missing; French legitimate metrics will not be produced.");
}

const germanChatPath = path.join(rawDir, "german-dortmund-chat.zip");
if (await exists(germanChatPath)) {
  samples.push(...parseGermanChat(await readFile(germanChatPath)));
} else {
  console.warn("Dortmund chat corpus is missing; German legitimate metrics will not be produced.");
}

const dutchWhatsappDir = path.join(rawDir, "dutch-whatsapp");
if (await exists(dutchWhatsappDir)) {
  const filenames = (await readdir(dutchWhatsappDir))
    .filter((filename) => filename.endsWith(".folia.xml"))
    .sort();
  const files = await Promise.all(filenames.map(async (filename) => ({
    filename,
    text: await readFile(path.join(dutchWhatsappDir, filename), "utf8"),
  })));
  samples.push(...parseDutchWhatsapp(files));
} else {
  console.warn("Dutch WhatsApp corpus is missing; Dutch legitimate metrics will not be produced.");
}

const annotationRank = {
  "public-corpus-label": 1,
  "user-reported": 2,
  "authority-described": 3,
  "expert-reviewed": 4,
  "authority-confirmed": 5,
};
const normalizedText = (text: string) => text.normalize("NFKC").toLocaleLowerCase().replace(/\s+/g, " ").trim();
const uniqueByText = new Map<string, EvaluationSample>();
const conflictingTexts = new Set<string>();
let duplicateCount = 0;
let conflictingLabelCount = 0;
for (const sample of samples) {
  const key = createHash("sha256").update(normalizedText(sample.text)).digest("hex");
  if (conflictingTexts.has(key)) {
    duplicateCount += 1;
    continue;
  }
  const existing = uniqueByText.get(key);
  if (!existing) {
    uniqueByText.set(key, sample);
    continue;
  }
  duplicateCount += 1;
  if (existing.label !== sample.label) {
    uniqueByText.delete(key);
    conflictingTexts.add(key);
    conflictingLabelCount += 1;
    continue;
  }
  if (annotationRank[sample.annotationStatus] > annotationRank[existing.annotationStatus]) {
    uniqueByText.set(key, sample);
  }
}
const dataset = [...uniqueByText.values()];
if (duplicateCount) console.warn(`Removed ${duplicateCount} exact cross-source duplicate rows.`);
if (conflictingLabelCount) {
  console.warn(`Excluded ${conflictingLabelCount} unique texts with conflicting labels.`);
}

await mkdir(generatedDir, { recursive: true });
await writeFile(
  path.join(generatedDir, "messages.jsonl"),
  `${dataset.map((sample) => JSON.stringify(sample)).join("\n")}\n`,
);

const counts = Object.fromEntries(
  [...new Set(dataset.map((sample) => sample.source))].map((source) => [
    source,
    {
      total: dataset.filter((sample) => sample.source === source).length,
      scam: dataset.filter((sample) => sample.source === source && sample.label === "scam").length,
      legitimate: dataset.filter((sample) => sample.source === source && sample.label === "legitimate").length,
    },
  ]),
);
const summary = {
  total: dataset.length,
  removedExactDuplicates: duplicateCount,
  excludedConflictingLabels: conflictingLabelCount,
  counts,
};
await writeFile(path.join(generatedDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary, null, 2));
