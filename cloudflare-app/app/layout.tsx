import type { Metadata } from "next";
import { Inter, Orbitron } from "next/font/google";
import "./globals.css";

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
    icons: {
      icon: [{ url: "/favicon.svg", type: "image/svg+xml" }],
      shortcut: "/favicon.svg",
    },
    openGraph: {
      title: "ScamShield — Pause before you trust the message",
      description: "Check suspicious messages and links with explainable risk signals and clear next steps.",
      type: "website",
      url: CANONICAL_ORIGIN,
      images: [{ url: `${CANONICAL_ORIGIN}/og.png`, width: 1731, height: 909, alt: "ScamShield — Pause before you trust the message" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "ScamShield",
      description: "Explainable scam risk analysis for suspicious messages and URLs.",
      images: [`${CANONICAL_ORIGIN}/og.png`],
    },
  };

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${orbitron.variable}`}>
        {children}
      </body>
    </html>
  );
}
