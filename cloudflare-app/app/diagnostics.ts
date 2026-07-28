"use client";

import { useSyncExternalStore } from "react";

export const DIAGNOSTICS_STORAGE_KEY = "scamshield-anonymous-diagnostics";
export const DIAGNOSTICS_CHANGE_EVENT = "scamshield-diagnostics-change";

type ScanMode = "quick" | "deep";
type RiskLevel = "Low" | "Medium" | "High";
type FeedbackChoice = "correct" | "should_be_safer" | "should_be_riskier";
type ErrorCategory = "network" | "http_4xx" | "http_5xx" | "invalid_response" | "unknown";

interface DiagnosticBase {
  mode: ScanMode;
  durationMs: number;
}
export type AnonymousDiagnostic =
  | (DiagnosticBase & {
      event: "scan_complete";
      riskLevel: RiskLevel;
      detectedLanguage: string;
      riskPercent: number;
      providerCompleted: number;
      providerTotal: number;
      linkCount: number;
    })
  | (DiagnosticBase & {
      event: "scan_error";
      errorCategory: ErrorCategory;
    })
  | (DiagnosticBase & {
      event: "result_feedback";
      riskLevel: RiskLevel;
      detectedLanguage: string;
      riskPercent: number;
      providerCompleted: number;
      providerTotal: number;
      linkCount: number;
      feedback: FeedbackChoice;
    });

export function getDiagnosticsSnapshot() {
  return window.localStorage.getItem(DIAGNOSTICS_STORAGE_KEY) === "enabled";
}

function subscribeToDiagnostics(onStoreChange: () => void) {
  window.addEventListener("storage", onStoreChange);
  window.addEventListener(DIAGNOSTICS_CHANGE_EVENT, onStoreChange);
  return () => {
    window.removeEventListener("storage", onStoreChange);
    window.removeEventListener(DIAGNOSTICS_CHANGE_EVENT, onStoreChange);
  };
}

export function useDiagnosticsEnabled() {
  return useSyncExternalStore(subscribeToDiagnostics, getDiagnosticsSnapshot, () => false);
}

export function setDiagnosticsEnabled(enabled: boolean) {
  window.localStorage.setItem(DIAGNOSTICS_STORAGE_KEY, enabled ? "enabled" : "disabled");
  window.dispatchEvent(new Event(DIAGNOSTICS_CHANGE_EVENT));
}

export async function sendAnonymousDiagnostic(event: AnonymousDiagnostic): Promise<boolean> {
  if (!getDiagnosticsSnapshot()) return false;

  try {
    const response = await fetch("/api/diagnostics", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ consent: true, ...event }),
      credentials: "same-origin",
      keepalive: true,
    });
    return response.ok;
  } catch {
    return false;
  }
}
