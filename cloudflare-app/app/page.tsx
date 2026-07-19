import type { Metadata } from "next";
import { ScanApp } from "./ScanApp";

export const metadata: Metadata = {
  title: "ScamShield — Check suspicious messages and links",
  description:
    "Analyze suspicious messages and URLs with explainable risk signals, live reputation checks, and an optional consent-based VirusTotal Deep Scan.",
};

export default function Home() {
  return <ScanApp />;
}
