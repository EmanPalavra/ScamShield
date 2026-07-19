import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "How it works" };

export default function HowItWorksPage() {
  return (
    <InfoShell
      eyebrow="Product guide"
      title="A careful check in four stages"
      intro="ScamShield combines explainable local signals with limited reputation lookups. It never visits or renders the suspicious destination."
    >
      <section><span className="info-number">01</span><div><h2>Read the message</h2><p>The engine looks for pressure, credential requests, unusual payment methods, impersonation, prize claims, and other social-engineering patterns in English and Bosnian/Croatian/Serbian wording.</p></div></section>
      <section><span className="info-number">02</span><div><h2>Inspect the URL safely</h2><p>ScamShield parses the hostname and path without opening the site. It checks for raw IP addresses, hidden destinations, brand look-alikes, risky domain patterns, and recent registration.</p></div></section>
      <section><span className="info-number">03</span><div><h2>Ask reputation providers</h2><p>Independent provider calls run in parallel with a short time budget. Quick Scan can use Google Safe Browsing and RDAP. Deep Scan also checks the latest existing VirusTotal URL report.</p></div></section>
      <section><span className="info-number">04</span><div><h2>Explain the decision</h2><p>The Simple view prioritizes one risk level, three reasons, and three next steps. Analyst view exposes evidence, URLs, provider responses, and extracted indicators.</p></div></section>
    </InfoShell>
  );
}
