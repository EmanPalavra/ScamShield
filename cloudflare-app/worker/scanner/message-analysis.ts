import {
  benignContextPatterns,
  bhsCommonLanguagePatterns,
  bhsLanguagePatterns,
  callToActionPatterns,
  categoryRules,
  consequencePatterns,
  credentialPatterns,
  credentialRequestPatterns,
  evasionPatterns,
  generalLanguagePatterns,
  impersonationPatterns,
  languageProfiles,
  paymentPatterns,
  regionalBhsProfiles,
  rewardPatterns,
  routineAccountNoticePatterns,
  secrecyPatterns,
  authorityPatterns,
  urgencyPatterns,
} from "./message-rules.ts";
import { hybridizeRuleScore, predictLocalScamProbability } from "./ml-classifier.ts";

const MAX_URLS = 3;
const MAX_URL_LENGTH = 2_048;

function stripTrailingPunctuation(value: string) {
  return value.replace(/[),.;!?\]}>'"]+$/g, "");
}

export function extractUrls(message: string) {
  const candidates = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) ?? [];
  const urls: string[] = [];
  for (const candidate of candidates) {
    const cleaned = stripTrailingPunctuation(candidate);
    const withScheme = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
    try {
      const parsed = new URL(withScheme);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) continue;
      parsed.hash = "";
      if (parsed.href.length > MAX_URL_LENGTH) continue;
      if (!urls.includes(parsed.href)) urls.push(parsed.href);
    } catch {
      continue;
    }
    if (urls.length >= MAX_URLS) break;
  }
  return urls;
}

function countPatternMatches(message: string, patterns: RegExp[]) {
  return patterns.reduce((count, pattern) => count + (pattern.test(message) ? 1 : 0), 0);
}

function normalizeForDetection(message: string) {
  const withoutTranslationUi = message
    .split(/\r?\n/)
    .filter((line) => !/^\s*(?:translated:\s*.{1,60}|english|translate can make mistakes(?:,\s*so verify translations)?|original text)\s*$/i.test(line))
    .join("\n");
  const normalized = withoutTranslationUi
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  const deobfuscated = normalized
    .replace(/(?<=\p{L})[._-](?=\p{L})/gu, "")
    .replace(/[＠]/g, "@")
    .replace(/0/g, "o")
    .replace(/[1!|]/g, "i")
    .replace(/3/g, "e")
    .replace(/[4@]/g, "a")
    .replace(/[5$]/g, "s")
    .replace(/7/g, "t");
  return deobfuscated === normalized ? normalized : `${normalized} ${deobfuscated}`;
}

function detectMessageLanguage(message: string) {
  if (countPatternMatches(message, [...bhsLanguagePatterns, ...bhsCommonLanguagePatterns])) {
    const regional = regionalBhsProfiles
      .map((profile) => ({ label: profile.label, hits: countPatternMatches(message, [...profile.patterns]) }))
      .sort((a, b) => b.hits - a.hits);
    if (regional[0]?.hits) return regional[0].label;
    return "Bosnian / Croatian / Serbian";
  }

  const ranked = languageProfiles
    .map((profile) => ({
      label: profile.label,
      hits: countPatternMatches(message, [...profile.patterns, ...(generalLanguagePatterns[profile.label] ?? [])]),
    }))
    .sort((a, b) => b.hits - a.hits);
  return ranked[0]?.hits ? ranked[0].label : "Unknown / mixed";
}

export function messageRuleAnalysis(message: string, urls: string[]) {
  const normalizedMessage = normalizeForDetection(message);
  const categoryScoresByType = new Map<string, { type: string; score: number; hits: number }>();
  for (const rule of categoryRules) {
    const hits = countPatternMatches(normalizedMessage, rule.patterns);
    const candidate = { type: rule.type, score: hits * rule.weight, hits };
    const current = categoryScoresByType.get(rule.type);
    if (!current || candidate.score > current.score) categoryScoresByType.set(rule.type, candidate);
  }
  const categoryScores = [...categoryScoresByType.values()];
  categoryScores.sort((a, b) => b.score - a.score);

  const urgencyHits = countPatternMatches(normalizedMessage, urgencyPatterns);
  const credentialMentionHits = countPatternMatches(normalizedMessage, credentialPatterns);
  const credentialHits = countPatternMatches(normalizedMessage, credentialRequestPatterns);
  const paymentHits = countPatternMatches(normalizedMessage, paymentPatterns);
  const consequenceHits = countPatternMatches(normalizedMessage, consequencePatterns);
  const rewardHits = countPatternMatches(normalizedMessage, rewardPatterns);
  const callToActionHits = countPatternMatches(normalizedMessage, callToActionPatterns);
  const impersonationHits = countPatternMatches(normalizedMessage, impersonationPatterns);
  const secrecyHits = countPatternMatches(normalizedMessage, secrecyPatterns);
  const authorityHits = countPatternMatches(normalizedMessage, authorityPatterns);
  const evasionHits = countPatternMatches(message, evasionPatterns);
  const benignContextHits = countPatternMatches(normalizedMessage, benignContextPatterns);
  const routineAccountNoticeHits = countPatternMatches(normalizedMessage, routineAccountNoticePatterns);
  const uppercaseWords = message.match(/\b[A-ZČĆŽŠĐ]{4,}\b/g)?.length ?? 0;
  const exclamations = Math.min(3, (message.match(/!/g) ?? []).length);

  let score = urls.length ? 8 : 4;
  score += Math.min(30, categoryScores.reduce((sum, category) => sum + category.score, 0));
  score += Math.min(16, urgencyHits * 8);
  score += Math.min(20, credentialHits * 10);
  score += Math.min(18, paymentHits * 9);
  score += Math.min(16, consequenceHits * 8);
  score += Math.min(14, rewardHits * 7);
  score += Math.min(12, callToActionHits * 4);
  score += Math.min(10, impersonationHits * 5);
  score += Math.min(12, secrecyHits * 6);
  score += Math.min(12, authorityHits * 6);
  score += Math.min(10, evasionHits * 5);
  score += Math.min(4, uppercaseWords);
  score += exclamations * 2;
  const independentSignalGroups = [
    urgencyHits,
    credentialHits,
    paymentHits,
    consequenceHits,
    rewardHits,
    callToActionHits,
    impersonationHits,
    secrecyHits,
    authorityHits,
    evasionHits,
  ].filter((hits) => hits > 0).length;
  const strongestCategoryHits = categoryScores[0]?.hits ?? 0;
  const strongestCategoryType = categoryScores[0]?.type ?? "";
  if (credentialHits && callToActionHits && (urgencyHits || consequenceHits || urls.length)) score += 15;
  if (paymentHits && (secrecyHits || authorityHits || rewardHits)) score += 14;
  if (paymentHits && secrecyHits && authorityHits) score = Math.max(score, 78);
  if (urls.length && (credentialHits || paymentHits) && callToActionHits) score += 10;
  if (evasionHits && independentSignalGroups >= 2) score += 8;
  if (strongestCategoryHits >= 2 && independentSignalGroups >= 3) score = Math.max(score, 76);
  else if (strongestCategoryHits >= 1 && independentSignalGroups >= 3) score = Math.max(score, 62);
  else if (
    strongestCategoryHits >= 1
    && (independentSignalGroups >= 2 || (urls.length > 0 && (callToActionHits > 0 || consequenceHits > 0)))
  ) score = Math.max(score, 46);
  else if (independentSignalGroups >= 4) score = Math.max(score, 58);
  if (
    strongestCategoryHits >= 2
    && ["Check / mobile-deposit scam", "Identity / verification phishing", "Gift-card impersonation scam", "Verification-code theft"].includes(strongestCategoryType)
  ) {
    score = Math.max(score, 78);
  }
  if (strongestCategoryType === "Delivery / postal scam" && strongestCategoryHits >= 2 && paymentHits) {
    score = Math.max(score, 68);
  }
  const routineAccountNotice = routineAccountNoticeHits >= 2
    && urgencyHits === 0
    && credentialHits === 0
    && paymentHits === 0
    && consequenceHits === 0
    && rewardHits === 0
    && secrecyHits === 0
    && authorityHits === 0
    && evasionHits === 0;
  if (routineAccountNotice) {
    score = Math.max(urls.length ? 8 : 4, score - Math.min(32, routineAccountNoticeHits * 8));
  }
  if (benignContextHits && !callToActionHits && !paymentHits && !credentialHits && !urls.length) {
    score = Math.max(2, score - 22);
  }

  const reasons: string[] = [];
  if (routineAccountNotice) {
    reasons.push("The wording is consistent with a routine account-onboarding notice and does not ask the recipient to disclose credentials.");
  }
  if (categoryScores[0]?.hits) reasons.push(`The wording matches a common ${categoryScores[0].type.toLowerCase()} pattern.`);
  if (urgencyHits) reasons.push("The message creates urgency or a short deadline to reduce careful checking.");
  if (credentialHits) reasons.push("It asks for login, verification, or other sensitive account information.");
  if (paymentHits) reasons.push("It mentions a payment method or transfer commonly abused in scams.");
  if (consequenceHits) reasons.push("It threatens account restrictions, data loss, or another consequence to pressure the recipient.");
  if (rewardHits) reasons.push("It uses a reward, payout, guaranteed return, or unusually attractive offer as a lure.");
  if (callToActionHits && !routineAccountNotice) reasons.push("It pushes the recipient toward an immediate reply, call, payment, registration, or linked page.");
  if (impersonationHits) reasons.push("The wording imitates a recognizable company or official support team.");
  if (secrecyHits) reasons.push("It tries to isolate the recipient or move the conversation away from trusted verification channels.");
  if (authorityHits) reasons.push("It invokes authority or workplace hierarchy to make an unusual request feel mandatory.");
  if (evasionHits) reasons.push("The wording appears intentionally obfuscated to evade ordinary security filters.");
  if (uppercaseWords || exclamations >= 2) reasons.push("The formatting uses pressure signals such as capitals or repeated exclamation marks.");
  if (urls.length) reasons.push(`${urls.length} link${urls.length === 1 ? " was" : "s were"} found and checked separately.`);

  if (!reasons.length) reasons.push("No strong social-engineering pattern was found in the supplied text.");
  const signals = [
    {
      name: "Urgency & pressure",
      count: urgencyHits,
      state: urgencyHits >= 2 ? "danger" : urgencyHits === 1 ? "warning" : "clear",
      detail: urgencyHits
        ? `${urgencyHits} urgency pattern${urgencyHits === 1 ? " was" : "s were"} detected.`
        : "No forced deadline or urgency phrase was detected.",
    },
    {
      name: "Sensitive information",
      count: credentialHits,
      state: credentialHits > 0 ? "danger" : "clear",
      detail: credentialHits
        ? `${credentialHits} request${credentialHits === 1 ? "" : "s"} related to login, identity, or verification data were detected.`
        : credentialMentionHits
          ? `Credential-related terms were mentioned ${credentialMentionHits} time${credentialMentionHits === 1 ? "" : "s"}, but no request to disclose them was detected.`
          : "No request for passwords, login details, or verification codes was detected.",
    },
    {
      name: "Payment language",
      count: paymentHits,
      state: paymentHits >= 2 ? "danger" : paymentHits === 1 ? "warning" : "clear",
      detail: paymentHits
        ? `${paymentHits} payment or transfer signal${paymentHits === 1 ? " was" : "s were"} detected.`
        : "No common payment-pressure phrase was detected.",
    },
    {
      name: "Aggressive formatting",
      count: uppercaseWords + exclamations,
      state: uppercaseWords + exclamations >= 4 ? "warning" : "clear",
      detail: uppercaseWords || exclamations
        ? `${uppercaseWords} uppercase word${uppercaseWords === 1 ? "" : "s"} and ${exclamations} emphasized exclamation mark${exclamations === 1 ? "" : "s"} were counted.`
        : "No strong formatting-pressure signal was detected.",
    },
    {
      name: "Threatened consequences",
      count: consequenceHits,
      state: consequenceHits >= 2 ? "danger" : consequenceHits === 1 ? "warning" : "clear",
      detail: consequenceHits
        ? `${consequenceHits} threat of account restriction, failed payment, or data loss was detected.`
        : "No threat of suspension, freezing, deletion, or failed credit was detected.",
    },
    {
      name: "Reward or profit lure",
      count: rewardHits,
      state: rewardHits >= 2 ? "danger" : rewardHits === 1 ? "warning" : "clear",
      detail: rewardHits
        ? `${rewardHits} reward, payout, bonus, or profit lure was detected.`
        : "No prize, bonus, guaranteed profit, or unexpected payout was detected.",
    },
    {
      name: "Forced call to action",
      count: callToActionHits,
      state: routineAccountNotice ? "clear" : callToActionHits >= 2 ? "danger" : callToActionHits === 1 ? "warning" : "clear",
      detail: routineAccountNotice && callToActionHits
        ? "A first-time account-access instruction was found without urgency, payment pressure, or a request to disclose credentials."
        : callToActionHits
          ? `${callToActionHits} instruction to call, reply, register, pay, or open a link was detected.`
        : "No suspicious instruction to reply, call, register, pay, or open a link was detected.",
    },
    {
      name: "Brand impersonation",
      count: impersonationHits,
      state: impersonationHits >= 2 ? "danger" : impersonationHits === 1 ? "warning" : "clear",
      detail: impersonationHits
        ? `${impersonationHits} phrase associated with brand or support-team impersonation was detected.`
        : "No strong brand or official-support impersonation phrase was detected.",
    },
    {
      name: "Secrecy & isolation",
      count: secrecyHits,
      state: secrecyHits > 0 ? "danger" : "clear",
      detail: secrecyHits
        ? `${secrecyHits} instruction${secrecyHits === 1 ? "" : "s"} to hide the request or leave trusted channels were detected.`
        : "No instruction to keep the request secret or avoid trusted contacts was detected.",
    },
    {
      name: "Authority pressure",
      count: authorityHits,
      state: authorityHits > 0 ? "warning" : "clear",
      detail: authorityHits
        ? `${authorityHits} authority or workplace-pressure pattern${authorityHits === 1 ? " was" : "s were"} detected.`
        : "No unusual request backed by authority or workplace hierarchy was detected.",
    },
    {
      name: "Filter evasion",
      count: evasionHits,
      state: evasionHits > 0 ? "warning" : "clear",
      detail: evasionHits
        ? `${evasionHits} obfuscation pattern${evasionHits === 1 ? " was" : "s were"} detected.`
        : "No deliberate word or character obfuscation was detected.",
    },
  ] as const;

  const strongestCategory = categoryScores[0]?.hits ? categoryScores[0].type : null;
  const inferredType = credentialHits && (urgencyHits || consequenceHits || urls.length)
    ? "Credential phishing / account takeover"
    : paymentHits && (urgencyHits || consequenceHits)
      ? "Payment-pressure / advance-fee scam"
      : authorityHits && paymentHits
        ? "Authority impersonation / payment fraud"
        : rewardHits && paymentHits
          ? "Reward / payment scam"
          : impersonationHits && (callToActionHits || urls.length)
            ? "Brand impersonation / social engineering"
            : urls.length && callToActionHits
              ? "Suspicious link solicitation"
              : urgencyHits || consequenceHits
                ? "Social-engineering pressure"
                : "No specific scam category identified";

  const words = message.match(/\S+/g)?.length ?? 0;
  const lines = message ? message.split(/\r?\n/).length : 0;
  return {
    score: Math.min(96, score),
    scamType: routineAccountNotice ? "Routine account onboarding / access notice" : strongestCategory ?? inferredType,
    reasons,
    indicators: { urgency: urgencyHits, credentials: credentialHits, payment: paymentHits },
    signals,
    categories: categoryScores.filter((category) => category.hits > 0).slice(0, 4),
    context: { routineAccountNotice, routineAccountNoticeHits, credentialMentionHits },
    stats: {
      characters: message.length,
      words,
      lines,
      uppercaseWords,
      exclamations,
    },
    detectedLanguage: detectMessageLanguage(normalizedMessage),
  };
}

export function messageAnalysis(message: string, urls: string[]) {
  const rules = messageRuleAnalysis(message, urls);
  const mlProbability = predictLocalScamProbability(message);
  const hybridScore = hybridizeRuleScore(
    rules.score,
    mlProbability,
    rules.context.routineAccountNotice,
  );
  const mlRaisedAlert = hybridScore >= 34 && rules.score < 34;
  const mlReducedAlert = hybridScore < 34 && rules.score >= 34;
  const reasons = [...rules.reasons];
  if (mlRaisedAlert) {
    reasons.unshift("A local statistical model found a combination of wording patterns associated with scam messages.");
  } else if (mlReducedAlert) {
    reasons.unshift("The local statistical model found the overall wording closer to legitimate messages than scams.");
  }
  return {
    ...rules,
    score: hybridScore,
    reasons,
    model: {
      probability: mlProbability,
      raisedAlert: mlRaisedAlert,
      reducedAlert: mlReducedAlert,
    },
  };
}
