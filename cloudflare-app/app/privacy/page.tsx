import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Privacy" };

export default function PrivacyPage() {
  return (
    <InfoShell
      eyebrow="Data handling"
      title="Privacy before enrichment"
      intro="ScamShield is designed to minimize retained data, but live reputation checks necessarily share URLs with external security providers."
    >
      <section><span className="info-number">01</span><div><h2>What ScamShield receives</h2><p>The service receives the message or URL you submit, basic request metadata needed for abuse controls, and a Turnstile verification token when bot protection is enabled.</p></div></section>
      <section><span className="info-number">02</span><div><h2>What is not intentionally stored</h2><p>The application does not require an account and does not intentionally save pasted message content to an application database. Temporary platform logs and provider-side logs may still exist.</p></div></section>
      <section><span className="info-number">03</span><div><h2>External providers</h2><p>URLs may be sent to Google Safe Browsing, RDAP services, and VirusTotal when the relevant checks are configured. Their own terms and privacy policies apply.</p></div></section>
      <section><span className="info-number">04</span><div><h2>Fresh VirusTotal analysis</h2><p>A new analysis is never started automatically. ScamShield first reads the existing report, then requires explicit consent. Submitted URLs and results may become visible to VirusTotal and its security community, so private or credential-bearing links must not be submitted.</p></div></section>
    </InfoShell>
  );
}
