import type { EvaluationSample } from "./dataset-types.ts";

type AuditExample = Omit<
  EvaluationSample,
  "label" | "annotationStatus" | "evaluationSplit" | "evidenceKind"
>;

const examples: AuditExample[] = [
  {
    id: "authority-audit-en-usps-001",
    language: "English",
    scamType: "Delivery / postal scam",
    text: "USPS: We could not deliver your package because postage is unpaid. Fix the problem here: https://example.invalid/postage",
    source: "authority-audit-en-usps",
    sourceUrl: "https://consumer.ftc.gov/consumer-alerts/2025/04/think-text-message-usps-it-could-be-scam",
  },
  {
    id: "authority-audit-en-usps-002",
    language: "English",
    scamType: "Delivery / postal scam",
    text: "Missed delivery. Update your shipping preferences to receive the parcel: https://example.invalid/shipping",
    source: "authority-audit-en-usps",
    sourceUrl: "https://consumer.ftc.gov/consumer-alerts/2025/04/think-text-message-usps-it-could-be-scam",
  },
  {
    id: "authority-audit-de-family-001",
    language: "German",
    scamType: "Romance / impersonation scam",
    text: "Hallo Mama, ich habe ein neues Handy. Bitte speichere die neue Nummer ab!",
    source: "authority-audit-de-family",
    sourceUrl: "https://www.verbraucherzentrale.de/wissen/digitale-welt/mobilfunk-und-festnetz/hallo-mama-hallo-papa-betrugsversuche-ueber-whatsapp-und-sms-72910",
  },
  {
    id: "authority-audit-de-family-002",
    language: "German",
    scamType: "Romance / impersonation scam",
    text: "Hallo, das hier ist jetzt meine neue Nummer. LG dein Lieblingskind. Schreib mir bitte über WhatsApp.",
    source: "authority-audit-de-family",
    sourceUrl: "https://www.verbraucherzentrale.de/wissen/digitale-welt/mobilfunk-und-festnetz/hallo-mama-hallo-papa-betrugsversuche-ueber-whatsapp-und-sms-72910",
  },
  {
    id: "authority-audit-fr-smishing-001",
    language: "French",
    scamType: "Account takeover / phishing",
    text: "Assurance Maladie : votre compte sera restreint. Confirmez rapidement vos informations personnelles: https://example.invalid/ameli",
    source: "authority-audit-fr-smishing",
    sourceUrl: "https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/smishing-hameconnage-sms",
  },
  {
    id: "authority-audit-fr-smishing-002",
    language: "French",
    scamType: "Brand impersonation / fake charge",
    text: "Banque: un paiement inhabituel sera prélevé. Si vous ne le reconnaissez pas, appelez immédiatement le 01 XX XX XX XX.",
    source: "authority-audit-fr-smishing",
    sourceUrl: "https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/smishing-hameconnage-sms",
  },
  {
    id: "authority-audit-nl-ideal-001",
    language: "Dutch",
    scamType: "Brand impersonation / fake charge",
    text: "iDEAL: een overboeking van €2.850 is goedgekeurd. Herkent u deze niet? Neem zo snel mogelijk contact op via 020-XXX-XXXX.",
    source: "authority-audit-nl-ideal",
    sourceUrl: "https://www.fraudehelpdesk.nl/alert/valse-sms-uit-naam-ideal/",
  },
  {
    id: "authority-audit-nl-ideal-002",
    language: "Dutch",
    scamType: "Brand impersonation / fake charge",
    text: "Uw overboeking van enkele duizenden euro's is bevestigd. Bel het vermelde nummer direct als u dit niet was.",
    source: "authority-audit-nl-ideal",
    sourceUrl: "https://www.fraudehelpdesk.nl/alert/valse-sms-uit-naam-ideal/",
  },
  {
    id: "authority-audit-bhs-package-001",
    language: "Bosnian / Croatian / Serbian",
    scamType: "Delivery / postal scam",
    text: "Pošta: dostava paketa nije uspjela zbog nepotpune adrese. Ažurirajte podatke putem linka: https://example.invalid/adresa",
    source: "authority-audit-bhs-holiday-package",
    sourceUrl: "https://www.cert.rs/rs/obavestenje/1146-Aktuelne-sajber-prevare-tokom-praznika.html",
  },
  {
    id: "authority-audit-bhs-package-002",
    language: "Bosnian / Croatian / Serbian",
    scamType: "Delivery / postal scam",
    text: "Vaša pošiljka čeka isporuku. Potvrdite adresu i platite malu naknadu: https://example.invalid/isporuka",
    source: "authority-audit-bhs-holiday-package",
    sourceUrl: "https://www.cert.rs/rs/obavestenje/1146-Aktuelne-sajber-prevare-tokom-praznika.html",
  },
];

export const authorityScamAudit: EvaluationSample[] = examples.map((example) => ({
  ...example,
  label: "scam",
  annotationStatus: "authority-described",
  // This set became a validation set once its misses were inspected. Keep it in
  // calibration so the report never presents tuned examples as unseen evidence.
  evaluationSplit: "calibration",
  evidenceKind: "authority-described",
}));
