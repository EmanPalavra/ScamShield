import type { Metadata } from "next";
import { Inter, Orbitron } from "next/font/google";
import "./globals.css";
import { I18nProvider } from "./i18n";

const CANONICAL_ORIGIN = "https://scam.shield-security.workers.dev";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const orbitron = Orbitron({
  variable: "--font-orbitron",
  subsets: ["latin"],
});

export const metadata: Metadata = {
    metadataBase: new URL(CANONICAL_ORIGIN),
    title: {
      default: "ScamShield — Suspicious message and URL checker",
      template: "%s — ScamShield",
    },
    description:
      "Explainable scam risk analysis with message heuristics, URL inspection, live reputation providers, and consent-based VirusTotal analysis.",
    openGraph: {
      title: "ScamShield — Pause before you trust the message",
      description: "Check suspicious messages and links with explainable risk signals and clear next steps.",
      type: "website",
      url: CANONICAL_ORIGIN,
      images: [{ url: `${CANONICAL_ORIGIN}/scamshield-project-preview.png`, width: 1731, height: 909, alt: "ScamShield — Pause before you trust the message" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "ScamShield",
      description: "Explainable scam risk analysis for suspicious messages and URLs.",
      images: [`${CANONICAL_ORIGIN}/scamshield-project-preview.png`],
    },
  };

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/scamshield-m2-favicon.png?v=6" type="image/png" sizes="any" />
        <link rel="shortcut icon" href="/scamshield-m2-favicon.png?v=6" type="image/png" />
      </head>
      <body className={`${inter.variable} ${orbitron.variable}`}>
        <I18nProvider>{children}</I18nProvider>
      </body>
    </html>
  );
}
