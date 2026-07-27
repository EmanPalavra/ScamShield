export const ML_FEATURE_DIMENSION = 16_384;
const MAX_MODEL_CHARACTERS = 640;

function hashFeature(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  const unsigned = hash >>> 0;
  return {
    index: unsigned % ML_FEATURE_DIMENSION,
    sign: (unsigned & 0x80000000) === 0 ? 1 : -1,
  };
}

function addFeature(features: Map<number, number>, name: string, amount = 1) {
  const hashed = hashFeature(name);
  features.set(hashed.index, (features.get(hashed.index) ?? 0) + hashed.sign * amount);
}

export function extractMlFeatures(message: string) {
  const normalized = message
    .normalize("NFKC")
    .toLocaleLowerCase()
    .replace(/https?:\/\/[^\s]+|\bwww\.[^\s]+/giu, " URL ")
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/giu, " DOMAIN ")
    .replace(/\d+/g, " NUMBER ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_MODEL_CHARACTERS);
  const features = new Map<number, number>();
  const bounded = `^${normalized}$`;

  for (const size of [3, 4]) {
    for (let index = 0; index <= bounded.length - size; index += 1) {
      addFeature(features, `c${size}:${bounded.slice(index, index + size)}`);
    }
  }

  const words = normalized.match(/[\p{L}\p{N}_]+|URL|DOMAIN/gu) ?? [];
  for (let index = 0; index < words.length; index += 1) {
    addFeature(features, `w:${words[index]}`);
    if (index > 0) addFeature(features, `b:${words[index - 1]}_${words[index]}`);
  }

  const originalLength = message.length;
  addFeature(features, `len:${Math.min(12, Math.floor(originalLength / 40))}`);
  addFeature(features, `words:${Math.min(12, Math.floor(words.length / 5))}`);
  if (/https?:\/\/|www\.|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/i.test(message)) addFeature(features, "meta:link", 2);
  if (/\b\d{6,}\b/.test(message)) addFeature(features, "meta:long-number");
  if (/[€$£¥₹]|(?:\beur\b|\busd\b|\bgbp\b)/i.test(message)) addFeature(features, "meta:money");
  if ((message.match(/!/g) ?? []).length >= 2) addFeature(features, "meta:exclamations");
  if ((message.match(/\b[A-ZČĆŽŠĐ]{4,}\b/g) ?? []).length >= 2) addFeature(features, "meta:uppercase");

  let norm = 0;
  for (const [index, value] of features) {
    const compressed = Math.sign(value) * Math.log1p(Math.abs(value));
    features.set(index, compressed);
    norm += compressed * compressed;
  }
  const divisor = Math.sqrt(norm) || 1;
  return [...features].map(([index, value]) => [index, value / divisor] as const);
}
