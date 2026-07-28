import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const targetDir = path.join(evaluationDir, "data", "raw", "language-holdout");
const source = {
  url: "https://raw.githubusercontent.com/opmusic/SpamHunter_dataset/ee548cc9bb16629c764acc9d42d0f06d1cd51ae8/train/tweet_spam_labeelled.csv",
  sha256: "181c47ae9e69156f722e6dfdf502b9827bcb3b0ecb30ed3c1d8f71d9304ee36e",
};

const response = await fetch(source.url, {
  headers: { "User-Agent": "ScamShield independent benchmark downloader" },
});
if (!response.ok) throw new Error(`SpamHunter download failed: HTTP ${response.status}.`);
const content = new Uint8Array(await response.arrayBuffer());
const actualHash = createHash("sha256").update(content).digest("hex");
if (actualHash !== source.sha256) {
  throw new Error(`SpamHunter SHA-256 mismatch: expected ${source.sha256}, got ${actualHash}.`);
}

await mkdir(targetDir, { recursive: true });
await writeFile(path.join(targetDir, "spamhunter-manual-labels.csv"), content);
console.log(`Downloaded frozen SpamHunter labels (${content.byteLength.toLocaleString()} bytes; SHA-256 verified).`);
