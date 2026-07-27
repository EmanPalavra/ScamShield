import type { ProviderState, RiskLevel } from "./types";

export function riskIcon(level: RiskLevel) {
  if (level === "High") return "×";
  if (level === "Medium") return "!";
  return "✓";
}

export function providerIcon(state: ProviderState) {
  if (state === "danger") return "×";
  if (state === "warning") return "!";
  if (state === "clear") return "✓";
  return "·";
}

export function formatDuration(milliseconds: number) {
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  return `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)} s`;
}

export function formatDomainAge(days: number | null) {
  if (days === null) return "Age unavailable";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} old`;
  if (days < 730) return `${Math.round(days / 30)} months old`;
  return `${(days / 365).toFixed(1)} years old`;
}
