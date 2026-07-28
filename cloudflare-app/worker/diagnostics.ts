export interface DiagnosticsEnv {
  DIAGNOSTICS?: AnalyticsEngineDataset;
}

export type DiagnosticEvent = {
  event: "scan_complete" | "scan_error" | "result_feedback";
  mode: "quick" | "deep";
  durationMs: number;
  riskLevel: "Low" | "Medium" | "High" | "Unknown";
  detectedLanguage: string;
  feedback: "correct" | "should_be_safer" | "should_be_riskier" | "none";
  errorCategory: "network" | "http_4xx" | "http_5xx" | "invalid_response" | "unknown" | "none";
  riskPercent: number;
  providerCompleted: number;
  providerTotal: number;
  linkCount: number;
};

const ALLOWED_KEYS = new Set([
  "consent",
  "event",
  "mode",
  "durationMs",
  "riskLevel",
  "detectedLanguage",
  "feedback",
  "errorCategory",
  "riskPercent",
  "providerCompleted",
  "providerTotal",
  "linkCount",
]);
const EVENTS = new Set<DiagnosticEvent["event"]>(["scan_complete", "scan_error", "result_feedback"]);
const RISK_LEVELS = new Set<DiagnosticEvent["riskLevel"]>(["Low", "Medium", "High"]);
const FEEDBACK = new Set<DiagnosticEvent["feedback"]>(["correct", "should_be_safer", "should_be_riskier"]);
const ERROR_CATEGORIES = new Set<DiagnosticEvent["errorCategory"]>(["network", "http_4xx", "http_5xx", "invalid_response", "unknown"]);
const LANGUAGES = new Set(["English", "Bosnian", "Croatian", "Serbian", "German", "Spanish", "French", "Dutch", "Unknown"]);

function boundedInteger(value: unknown, maximum: number) {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(maximum, Math.max(0, Math.round(value)))
    : 0;
}

export function sanitizeDiagnosticPayload(value: unknown): DiagnosticEvent | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (body.consent !== true || Object.keys(body).some((key) => !ALLOWED_KEYS.has(key))) return null;
  if (typeof body.event !== "string" || !EVENTS.has(body.event as DiagnosticEvent["event"])) return null;
  if (body.mode !== "quick" && body.mode !== "deep") return null;

  const event = body.event as DiagnosticEvent["event"];
  const feedback = typeof body.feedback === "string" && FEEDBACK.has(body.feedback as DiagnosticEvent["feedback"])
    ? body.feedback as DiagnosticEvent["feedback"]
    : "none";
  const errorCategory = typeof body.errorCategory === "string" && ERROR_CATEGORIES.has(body.errorCategory as DiagnosticEvent["errorCategory"])
    ? body.errorCategory as DiagnosticEvent["errorCategory"]
    : "none";

  if (event === "result_feedback" && feedback === "none") return null;
  if (event === "scan_error" && errorCategory === "none") return null;

  return {
    event,
    mode: body.mode,
    durationMs: boundedInteger(body.durationMs, 120_000),
    riskLevel: typeof body.riskLevel === "string" && RISK_LEVELS.has(body.riskLevel as DiagnosticEvent["riskLevel"])
      ? body.riskLevel as DiagnosticEvent["riskLevel"]
      : "Unknown",
    detectedLanguage: typeof body.detectedLanguage === "string" && LANGUAGES.has(body.detectedLanguage)
      ? body.detectedLanguage
      : "Unknown",
    feedback,
    errorCategory,
    riskPercent: boundedInteger(body.riskPercent, 100),
    providerCompleted: boundedInteger(body.providerCompleted, 20),
    providerTotal: boundedInteger(body.providerTotal, 20),
    linkCount: boundedInteger(body.linkCount, 3),
  };
}

export function writeDiagnostic(env: DiagnosticsEnv, event: DiagnosticEvent) {
  if (!env.DIAGNOSTICS) return false;

  env.DIAGNOSTICS.writeDataPoint({
    indexes: [event.event],
    blobs: [
      "v1",
      event.event,
      event.mode,
      event.riskLevel,
      event.detectedLanguage,
      event.feedback,
      event.errorCategory,
    ],
    doubles: [
      event.durationMs,
      event.riskPercent,
      event.providerCompleted,
      event.providerTotal,
      event.linkCount,
    ],
  });
  return true;
}
