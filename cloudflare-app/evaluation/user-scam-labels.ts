export const userScamTypes = [
  "Marketplace / payment scam",
  "Brand impersonation / fake charge",
  "Document / SMS phishing",
  "Job scam",
  "Account takeover / phishing",
  "Marketplace / payment scam",
  "Delivery / postal scam",
  "Prize / advance-fee scam",
  "Job scam",
  "Investment / crypto scam",
  "Investment / crypto scam",
  "Job scam",
  "Marketplace / payment scam",
  "Check / mobile-deposit scam",
  "Renewal / subscription phishing",
  "Identity / verification phishing",
  "Marketplace / payment scam",
  "Gift-card impersonation scam",
  "Identity / verification phishing",
  "Job scam",
  "Verification-code theft",
] as const;

// These examples are labeled from the collector's report, not independently verified.
// IDs 17 and 20 are intentionally retained as difficult/ambiguous cases.
export const userScamReviewNotes: Record<number, string> = {
  17: "Could resemble a legitimate payment notice; retain as user-reported until independently reviewed.",
  20: "Could resemble a legitimate licensing request; retain as user-reported until independently reviewed.",
};
