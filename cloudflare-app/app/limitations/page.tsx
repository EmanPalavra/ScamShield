import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Limitations" };

export default function LimitationsPage() {
  return (
    <InfoShell
      eyebrow="Know the boundaries"
      title="What ScamShield cannot promise"
      intro="Security tools are most useful when their limits are visible. These are the important cases where human verification still matters."
    >
      <section><span className="info-number">01</span><div><h2>New and targeted attacks</h2><p>A new phishing page may not yet appear in any reputation provider. A low result means no strong signal was found; it does not prove the sender or link is safe.</p></div></section>
      <section><span className="info-number">02</span><div><h2>Context and attachments</h2><p>ScamShield cannot see prior conversation context, sender identity, email headers, attached files, QR-code destinations, or what happens after a login unless those details are included as text.</p></div></section>
      <section><span className="info-number">03</span><div><h2>Provider availability and quotas</h2><p>External APIs can time out, return incomplete data, or enforce quotas. The interface reports unavailable checks instead of silently treating them as clean.</p></div></section>
      <section><span className="info-number">04</span><div><h2>VirusTotal use</h2><p>Fresh analysis depends on a configured VirusTotal key and its permitted use. VirusTotal Community API access is intended for eligible non-commercial use and is subject to VirusTotal terms, quotas, and privacy rules.</p></div></section>
      <aside className="method-note"><strong>When the stakes are high</strong><p>If the message involves money, account access, identity documents, workplace systems, threats, or personal safety, stop and verify through an official channel or a qualified professional.</p></aside>
    </InfoShell>
  );
}
