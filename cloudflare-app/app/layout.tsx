import type { Metadata } from "next";
import { Inter, Orbitron } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const orbitron = Orbitron({
  variable: "--font-orbitron",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost:3000";
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;

  return {
    metadataBase: new URL(origin),
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
      url: origin,
      images: [{ url: `${origin}/og.png`, width: 1536, height: 806, alt: "ScamShield — Pause before you trust the message" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "ScamShield",
      description: "Explainable scam risk analysis for suspicious messages and URLs.",
      images: [`${origin}/og.png`],
    },
  };
}

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
