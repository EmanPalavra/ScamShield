import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { unzipSync } from "fflate";

const evaluationDir = path.dirname(fileURLToPath(import.meta.url));
const rawDir = path.join(evaluationDir, "data", "raw");
const uciUrl = "https://cdn.uci-ics-mlr-prod.aws.uci.edu/228/sms%2Bspam%2Bcollection.zip";
const spaPhishFilesUrl = "https://data.mendeley.com/public-api/datasets/hz2d6gz7pc/files?folder_id=root&version=5";
const englishSmishingFilesUrl =
  "https://data.mendeley.com/public-api/datasets/f45bkkt8pr/files?folder_id=root&version=1";
const sarajevoSmsUrl =
  "https://www.clarin.si/repository/xmlui/bitstream/handle/11356/1956/SCSMS.zip?isAllowed=y&sequence=3";
const frenchSmsUrl =
  "https://repository.ortolang.fr/api/content/comere/8/cmr-88milsms/cmr-88milsms-tei-v1.xml";
const germanChatUrl =
  "https://clarin.bbaw.de:8088/fedora/objects/dwds:10/datastreams/xml/content";
const dutchWhatsappMetadataUrl =
  "https://ssh.datastations.nl/api/datasets/:persistentId/?persistentId=doi:10.17026/DANS-XZZ-UGTW";
const imc25Url =
  "https://raw.githubusercontent.com/reportsmishing/Smishing-Dataset-IMC25/a6175560b57387199871e51fbef6bc523d2516b4/dataset/final_dataset_output.csv";
const smishxUrl =
  "https://raw.githubusercontent.com/yizhu-joy/SmishX/116a8c827741e0572563f678d25ed04306b1e3ff/data/dataset.csv";
const mozSmishingUrl =
  "https://huggingface.co/datasets/MOZNLP/MOZ-Smishing/resolve/1092f9d9a545b29ae6be030ee9713b615fc2d987/test.csv";
const smishTankUrl =
  "https://raw.githubusercontent.com/MarazMia/SMISH_DT/cc54e15c188376d82019631d9198f667b1de862e/Dataset/smishtank.csv";
const headers = { "User-Agent": "ScamShield dataset evaluator" };

async function responseBytes(url: string) {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const response = await fetch(url, { headers });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      lastError = error;
      if (attempt < 4) {
        console.warn(`Download attempt ${attempt} failed for ${new URL(url).hostname}; retrying...`);
        await new Promise((resolve) => setTimeout(resolve, attempt * 750));
      }
    }
  }
  throw new Error(`Download failed for ${url} after 4 attempts.`, { cause: lastError });
}

function verifyHash(content: Uint8Array, algorithm: "md5" | "sha1" | "sha256", expected: string, name: string) {
  const actual = createHash(algorithm).update(content).digest("hex");
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${name} ${algorithm.toUpperCase()} mismatch: expected ${expected}, got ${actual}.`);
  }
}

async function downloadUci() {
  const archive = await responseBytes(uciUrl);
  const files = unzipSync(archive);
  const corpus = files.SMSSpamCollection;
  if (!corpus) throw new Error("UCI archive does not contain SMSSpamCollection.");

  await mkdir(rawDir, { recursive: true });
  await writeFile(path.join(rawDir, "SMSSpamCollection"), corpus);
  console.log(`Downloaded UCI SMS Spam Collection (${corpus.byteLength.toLocaleString()} bytes).`);
}

async function downloadSpaPhish() {
  const listResponse = await fetch(spaPhishFilesUrl, {
    headers: {
      Accept: "application/vnd.mendeley-public-dataset.1+json",
      ...headers,
    },
  });
  if (!listResponse.ok) throw new Error(`SpaPhish file list failed: HTTP ${listResponse.status}`);
  const files = await listResponse.json() as Array<{
    filename: string;
    content_details: { download_url: string; sha256_hash: string };
  }>;
  const csv = files.find((file) => file.filename.toLowerCase().endsWith(".csv"));
  if (!csv) throw new Error("SpaPhish v5 does not expose a CSV file.");

  const content = await responseBytes(csv.content_details.download_url);
  verifyHash(content, "sha256", csv.content_details.sha256_hash, "SpaPhish");

  await mkdir(rawDir, { recursive: true });
  await writeFile(path.join(rawDir, "spaphish.csv"), content);
  console.log(`Downloaded SpaPhish v5 (${content.byteLength.toLocaleString()} bytes; SHA-256 verified).`);
}

async function downloadEnglishSmishing() {
  const listResponse = await fetch(englishSmishingFilesUrl, {
    headers: {
      Accept: "application/vnd.mendeley-public-dataset.1+json",
      ...headers,
    },
  });
  if (!listResponse.ok) {
    throw new Error(`English smishing file list failed: HTTP ${listResponse.status}`);
  }
  const files = await listResponse.json() as Array<{
    filename: string;
    content_details: { download_url: string; sha256_hash: string };
  }>;
  const archiveFile = files.find((file) => file.filename === "Dataset_5971.zip");
  if (!archiveFile) throw new Error("English smishing dataset does not expose Dataset_5971.zip.");
  const archive = await responseBytes(archiveFile.content_details.download_url);
  verifyHash(archive, "sha256", archiveFile.content_details.sha256_hash, "English smishing archive");
  const csv = unzipSync(archive)["Dataset_5971.csv"];
  if (!csv) throw new Error("English smishing archive does not contain Dataset_5971.csv.");

  await writeFile(path.join(rawDir, "english-smishing.csv"), csv);
  console.log(`Downloaded English smishing corpus (${csv.byteLength.toLocaleString()} bytes; SHA-256 verified).`);
}

async function downloadSarajevoSms() {
  const archive = await responseBytes(sarajevoSmsUrl);
  verifyHash(archive, "md5", "0760c697b27737d9a30176008bbf5638", "Sarajevo SMS corpus");
  await writeFile(path.join(rawDir, "sarajevo-sms.zip"), archive);
  console.log(`Downloaded Sarajevo SMS corpus (${archive.byteLength.toLocaleString()} bytes; MD5 verified).`);
}

async function downloadFrenchSms() {
  const content = await responseBytes(frenchSmsUrl);
  const opening = new TextDecoder().decode(content.subarray(0, 500));
  if (!opening.includes("<TEI")) throw new Error("88milSMS download is not the expected TEI XML corpus.");
  await writeFile(path.join(rawDir, "french-88milsms.xml"), content);
  console.log(`Downloaded 88milSMS French corpus (${content.byteLength.toLocaleString()} bytes).`);
}

async function downloadGermanChat() {
  const archive = await responseBytes(germanChatUrl);
  verifyHash(archive, "md5", "52823b3ffb2c3cf970f2d4f31eafece4", "Dortmund chat corpus");
  const files = unzipSync(archive);
  if (!Object.keys(files).some((name) => name.endsWith(".tei.xml"))) {
    throw new Error("Dortmund chat archive does not contain its TEI XML file.");
  }
  await writeFile(path.join(rawDir, "german-dortmund-chat.zip"), archive);
  console.log(`Downloaded Dortmund German chat corpus (${archive.byteLength.toLocaleString()} bytes; MD5 verified).`);
}

async function downloadDutchWhatsapp() {
  const metadataResponse = await fetch(dutchWhatsappMetadataUrl, { headers });
  if (!metadataResponse.ok) {
    throw new Error(`Dutch WhatsApp metadata failed: HTTP ${metadataResponse.status}`);
  }
  const metadata = await metadataResponse.json() as {
    data: {
      latestVersion: {
        license: { name: string };
        files: Array<{
          restricted: boolean;
          dataFile: {
            id: number;
            filename: string;
            filesize: number;
            checksum: { type: string; value: string };
          };
        }>;
      };
    };
  };
  const version = metadata.data.latestVersion;
  if (version.license.name !== "CC-BY-4.0") {
    throw new Error(`Unexpected Dutch WhatsApp license: ${version.license.name}`);
  }
  const selected = version.files
    .filter(({ restricted, dataFile }) =>
      !restricted
      && dataFile.filename.endsWith(".folia.xml")
      && dataFile.filesize <= 1_500_000
    )
    .sort((a, b) => a.dataFile.filename.localeCompare(b.dataFile.filename))
    .slice(0, 12);
  if (selected.length < 5) throw new Error(`Only ${selected.length} small Dutch WhatsApp files were available.`);

  const targetDir = path.join(rawDir, "dutch-whatsapp");
  await mkdir(targetDir, { recursive: true });
  let totalBytes = 0;
  for (const { dataFile } of selected) {
    const content = await responseBytes(`https://ssh.datastations.nl/api/access/datafile/${dataFile.id}`);
    if (dataFile.checksum.type !== "SHA-1") {
      throw new Error(`Unexpected checksum type for ${dataFile.filename}: ${dataFile.checksum.type}`);
    }
    verifyHash(content, "sha1", dataFile.checksum.value, dataFile.filename);
    await writeFile(path.join(targetDir, dataFile.filename), content);
    totalBytes += content.byteLength;
  }
  console.log(
    `Downloaded ${selected.length} Dutch WhatsApp files (${totalBytes.toLocaleString()} bytes; SHA-1 verified).`,
  );
}

async function downloadFrozenHoldout() {
  const imc25 = await responseBytes(imc25Url);
  verifyHash(
    imc25,
    "sha256",
    "1bbd1e9e82c3ea023112207b80da268a5c4a07d2353c2b0898360ab037fa9a64",
    "IMC 2025 frozen holdout",
  );
  const smishx = await responseBytes(smishxUrl);
  verifyHash(
    smishx,
    "sha256",
    "8d65e373b17477c34e8f1c619e6f59d249e8fca21276cabdd03a55d11a469285",
    "SmishX frozen holdout",
  );
  await writeFile(path.join(rawDir, "imc25-smishing.csv"), imc25);
  await writeFile(path.join(rawDir, "smishx-holdout.csv"), smishx);
  console.log(`Downloaded frozen external holdout sources (${(imc25.byteLength + smishx.byteLength).toLocaleString()} bytes; SHA-256 verified).`);
}

async function downloadFinalHoldout() {
  const content = await responseBytes(mozSmishingUrl);
  verifyHash(
    content,
    "sha256",
    "814a11d9b05741c4b47eb0d0784b1fd12a2a076f83a714a9908bdda594986ab8",
    "MOZ-Smishing final holdout",
  );
  await writeFile(path.join(rawDir, "moz-smishing.csv"), content);
  const smishTank = await responseBytes(smishTankUrl);
  verifyHash(
    smishTank,
    "sha256",
    "55dd9a19d48b51a86acd35b97cfa50f77453488434498521ce1f6ba5d52bef15",
    "SmishTank final recall holdout",
  );
  await writeFile(path.join(rawDir, "smishtank-final.csv"), smishTank);
  console.log(
    `Downloaded final holdouts (${(content.byteLength + smishTank.byteLength).toLocaleString()} bytes; SHA-256 verified).`,
  );
}

await mkdir(rawDir, { recursive: true });
const downloads = [
  ["UCI SMS", downloadUci],
  ["SpaPhish", downloadSpaPhish],
  ["English smishing", downloadEnglishSmishing],
  ["Sarajevo SMS", downloadSarajevoSms],
  ["French 88milSMS", downloadFrenchSms],
  ["Dortmund German chat", downloadGermanChat],
  ["Dutch WhatsApp", downloadDutchWhatsapp],
  ["Frozen external holdout", downloadFrozenHoldout],
  ["Final external holdout", downloadFinalHoldout],
] as const;
const failures: string[] = [];
for (const [name, download] of downloads) {
  try {
    await download();
  } catch (error) {
    failures.push(name);
    console.error(`${name} failed:`, error);
  }
}
if (failures.length) {
  throw new Error(`Dataset download failed for: ${failures.join(", ")}. Successful sources were kept.`);
}
