import { analyzeDomainIntelligence, type DomainIntelligence } from "./domain-intelligence";
import type { RateLimitDecision, RateLimiter } from "./rate-limiter";

export interface ScannerEnv {
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
  GOOGLE_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  STATUS_SIGNING_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  DISABLE_EXTERNAL_CHECKS?: string;
}

export interface ScannerContext {
  waitUntil(promise: Promise<unknown>): void;
}

type RiskLevel = "Low" | "Medium" | "High";
type ProviderState = "clear" | "warning" | "danger" | "unavailable" | "not-run";

interface ProviderResult {
  name: string;
  state: ProviderState;
  label: string;
  detail: string;
  configured: boolean;
}

interface LinkReport {
  url: string;
  domain: string;
  riskScore: number;
  reasons: string[];
  providers: ProviderResult[];
  domainAgeDays: number | null;
  virusTotal: {
    found: boolean;
    stats: Record<string, number> | null;
    lastAnalysisDate: number | null;
  } | null;
  domainIntelligence: DomainIntelligence;
  technical: {
    protocol: "HTTP" | "HTTPS";
    tld: string;
    usesHttps: boolean;
    isIpAddress: boolean;
    isPunycode: boolean;
    isShortener: boolean;
    hasUserInfo: boolean;
    hostnameLength: number;
    pathDepth: number;
    queryParameters: number;
  };
}

interface Rule {
  type: string;
  patterns: RegExp[];
  weight: number;
}

const MAX_MESSAGE_LENGTH = 10_000;
const MAX_URLS = 3;
const MAX_URL_LENGTH = 2_048;
const MAX_SCAN_BODY_BYTES = 48 * 1_024;
const MAX_DEEP_BODY_BYTES = 8 * 1_024;
const REQUEST_TIMEOUT_MS = 4_500;
const PROVIDER_JSON_LIMIT_BYTES = 256 * 1_024;
const STATUS_TOKEN_TTL_SECONDS = 30 * 60;
const TURNSTILE_ACTION = "turnstile-spin-v2";

const categoryRules: Rule[] = [
  {
    type: "Brand impersonation / fake charge",
    weight: 16,
    patterns: [
      /(?:apple|paypal|zelle|microsoft|amazon|netflix|icloud|google|\bbank\b|fedex|ups|dhl).{0,100}(?:account|payment|bill|charged|paid|support|transaction)/i,
      /(?:bill|payment|transaction|purchase).{0,80}(?:\$\s?\d+|usd|declined|unauthori[sz]ed|dispute)/i,
      /dispute.{0,30}(?:call|contact).{0,20}\d{7,}/i,
      /if you did not.{0,80}(?:call|click|change|contact)/i,
      /(?:nalog|racun).{0,80}(?:naplacen|placen|transakcij|neovlasten)/i,
      /(?:konto|cuenta|compte|rekening).{0,80}(?:zahlung|pago|paiement|betaling|transacci[oó]n|transaction)/i,
    ],
  },
  {
    type: "Account takeover / phishing",
    weight: 15,
    patterns: [
      /(?:verify|confirm|validate|update|restore|unlock|secure)[^.!?\n]{0,50}(?:account|identity|login|password|payment information|details)/i,
      /(?:account|cloud|storage|subscription).{0,90}(?:suspend|deactivat|locked|frozen|deleted|expire|full|on hold)/i,
      /(?:payment method|credit card|debit card).{0,50}(?:declined|failed|expired|update)/i,
      /(?:action required|update payment information|sign in here)/i,
      /(?:unusual|suspicious).{0,35}(?:login|activity|transaction)/i,
      /password.{0,30}(?:expire|reset|change|confirm)/i,
      /(?:nalog|racun).{0,60}(?:blokiran|zakljucan|zamrznut|deaktiviran)/i,
      /potvrd(?:i|ite).{0,30}(?:nalog|identitet|lozink|uplatu)/i,
      /(?:best[aä]tigen|verifizieren|actualizar|verificar|confirmer|v[ée]rifier|bevestigen|verifi[eë]ren).{0,55}(?:konto|cuenta|compte|rekening|passwort|contrase[nñ]a|mot de passe|wachtwoord)/i,
      /(?:konto|cuenta|compte|rekening).{0,70}(?:gesperrt|bloquead|suspendu|bloqu[ée]|geblokkeerd|opgeschort)/i,
    ],
  },
  {
    type: "Delivery / postal scam",
    weight: 13,
    patterns: [
      /(?:parcel|package|delivery|shipment|fedex|ups|dhl|usps).{0,120}(?:fee|address|failed|held|customs|reschedule|total due|payment|creditcard)/i,
      /(?:paket|posiljka|dostava).{0,100}(?:naknad|adres|zadrzan|carin|neuspjel|uplati)/i,
      /(?:paket|sendung|paquete|env[ií]o|colis|livraison|pakket|bezorging).{0,100}(?:geb[uü]hr|adresse|direcci[oó]n|frais|adres|kosten|zahlung|pago|paiement|betaling)/i,
      /(?:shipping|handling|insurance).{0,80}(?:fee|\$\s?\d+|total due)/i,
      /customs.{0,25}(?:fee|charge|payment)/i,
    ],
  },
  {
    type: "Investment / crypto scam",
    weight: 15,
    patterns: [
      /(?:crypto|bitcoin|btc|usdt|forex|trading).{0,100}(?:guaranteed|profit|return|signal|deposit|withdraw|bonus|casino)/i,
      /(?:withdrawal|payout).{0,100}(?:deposit|fee|tax|unlock|frozen|review)/i,
      /pay.{0,40}(?:\d+%|deposit).{0,100}(?:withdraw|release|receive)/i,
      /(?:double|multiply).{0,20}(?:money|crypto|investment)/i,
      /(?:signal prediction|buy \d+%|trading signal)/i,
      /wallet.{0,35}(?:validation|synchronization|unlock|connect)/i,
      /sigurn(?:a|i).{0,25}(?:zarada|profit|povrat)/i,
      /(?:krypto|bitcoin|crypto|criptomoneda).{0,100}(?:garantiert|garantizado|garanti|gegarandeerd|gewinn|beneficio|rendement|winst)/i,
    ],
  },
  {
    type: "Prize / advance-fee scam",
    weight: 14,
    patterns: [
      /(?:won|winner|prize|lottery|giveaway|reward|bonus).{0,120}(?:claim|register|withdraw|fee|promo code|pay|instantly)/i,
      /(?:osvojili|dobitnik|nagrada|poklon|bonus).{0,100}(?:preuzm|registr|naknad|uplati|kod)/i,
      /(?:mrbeast|celebrity|influencer).{0,100}(?:giveaway|bonus|crypto|casino)/i,
      /(?:processing|release|administration).{0,20}fee/i,
      /(?:inheritance|grant).{0,80}(?:fee|transfer|release)/i,
      /(?:gewonnen|gewinner|premio|ganador|gagn[ée]|prix|winnaar|prijs).{0,100}(?:beanspruchen|reclamar|r[ée]clamer|claimen|geb[uü]hr|tarifa|frais|kosten)/i,
    ],
  },
  {
    type: "Job scam",
    weight: 12,
    patterns: [
      /(?:remote|data entry|work from home|online).{0,120}(?:position|job|interview|hourly rate|earn|training)/i,
      /(?:job|position|application|resume|creator).{0,150}(?:reply ["']?yes|onboard|interview|bonus|\$\s?\d+|meeting)/i,
      /(?:onboarding|recruiting).{0,120}(?:creators?|candidate|platform|remote|bonus|joining)/i,
      /(?:posao od kuce|udaljeni posao).{0,100}(?:zarad|dnevno|sedmicno|obuk|intervju)/i,
      /pay.{0,80}(?:training|equipment).{0,100}(?:job|position)/i,
      /(?:heimarbeit|trabajo desde casa|travail [àa] domicile|thuiswerk).{0,100}(?:verdienen|ganar|gagner|salaris|betaling)/i,
    ],
  },
  {
    type: "Tech support scam",
    weight: 14,
    patterns: [
      /(?:computer|device).*(?:infected|virus|compromised)/i,
      /(?:računar|uređaj).*(?:zaražen|virus|hakovan)/i,
      /call (?:microsoft|support).*(?:immediately|now)/i,
      /(?:computer|ordinateur|ordenador|computer).{0,80}(?:virus|infiziert|infect[ée]|infectado|besmet|gehackt)/i,
    ],
  },
  {
    type: "Marketplace / payment scam",
    weight: 15,
    patterns: [
      /(?:zelle|paypal|cash app|venmo).{0,100}(?:paid you|account on hold|business account|credit your funds|above your limit)/i,
      /(?:account on hold|unable to credit|upgrade.{0,30}business).{0,100}(?:pay|refund|send|funds)/i,
      /(?:pay half|deposit).{0,80}(?:take.{0,30}(?:post|listing).{0,20}down|mark.{0,15}sold)/i,
      /(?:apple|google|steam|amazon).{0,20}gift card/i,
      /(?:pre-owned|used item).{0,100}(?:visit|online store|pay|shipping)/i,
      /(?:pre-owned|used item).{0,180}(?:online store).{0,140}(?:customer service|more details|specifications)/i,
      /(?:geschenkkarte|tarjeta de regalo|carte cadeau|cadeaukaart).{0,60}(?:kaufen|comprar|acheter|kopen|code)/i,
    ],
  },
  {
    type: "Check / mobile-deposit scam",
    weight: 17,
    patterns: [
      /(?:pay|payment|full payment).{0,100}(?:by check|with a check)/i,
      /(?:pictures?|photos?).{0,70}(?:front and back).{0,90}(?:check|deposit)/i,
      /(?:mobile deposit|mobile banking app).{0,100}(?:check|deposit|funds)/i,
      /(?:check|cheque).{0,120}(?:overpayment|extra amount|send back|refund|difference)/i,
    ],
  },
  {
    type: "Identity / verification phishing",
    weight: 17,
    patterns: [
      /(?:pre-employment|employment|candidate).{0,100}(?:verification|screening).{0,160}(?:photo id|passport|national id|proof of address)/i,
      /(?:government-issued|government issued|photo id|passport|national id).{0,100}(?:proof of address|bank statement|utility bill)/i,
      /(?:complete|submit).{0,50}(?:verification|identity review).{0,100}(?:within \d+ hours?|application active|removed from consideration)/i,
      /(?:account requires verification|submit appeal).{0,100}(?:account restriction|within \d+ hours?)/i,
    ],
  },
  {
    type: "Gift-card impersonation scam",
    weight: 17,
    patterns: [
      /(?:surprise|confidential|keep this).{0,140}(?:gift card|store card|voucher).{0,100}(?:reimburse|buy|get|purchase)/i,
      /(?:boss|manager|ceo|team members?).{0,140}(?:gift card|store card|voucher)/i,
      /(?:buy|get|purchase).{0,50}(?:apple|google|steam|amazon)?\s*(?:gift card|store card|voucher).{0,80}(?:code|reimburse|now)/i,
    ],
  },
  {
    type: "Verification-code theft",
    weight: 18,
    patterns: [
      /(?:send|tell|share).{0,35}(?:me )?(?:the |your )?(?:verification|unlock|security|one[- ]time)?\s*code/i,
      /(?:unlock|verification|security|one[- ]time).{0,25}code.{0,80}(?:someone|another phone|expires?|fast)/i,
      /(?:code|otp).{0,50}(?:expires?|valid).{0,30}(?:seconds?|minutes?)/i,
    ],
  },
  {
    type: "Renewal / subscription phishing",
    weight: 14,
    patterns: [
      /(?:enrollment|subscription|membership|registration).{0,80}(?:expired|expire soon|unregistered)/i,
      /(?:records indicate|friendly reminder).{0,120}(?:expired|renew).{0,160}(?:visit|link|update)/i,
      /(?:renew|reactivate).{0,80}(?:microchip|subscription|membership|registration)/i,
    ],
  },
  {
    type: "Document / SMS phishing",
    weight: 13,
    patterns: [
      /(?:document|invoice|voicemail|review|notice).{0,80}(?:awaiting|pending|access|open|view)/i,
      /(?:periodic review|no action required).{0,120}(?:https?:\/\/|www\.|reply stop)/i,
      /(?:reply stop|opt[- ]out).{0,120}(?:https?:\/\/|www\.)/i,
      /(?:access|open|view).{0,30}(?:document|invoice|message).{0,50}(?:here|link)/i,
    ],
  },
  {
    type: "Romance / impersonation scam",
    weight: 11,
    patterns: [
      /(?:deployed|offshore|abroad).*(?:money|gift card|transfer)/i,
      /(?:hitno|urgentno).*(?:pošalji|uplati).*(?:novac|kartic)/i,
      /pretend(?:ing)? to be/i,
    ],
  },
  {
    type: "Brand impersonation / fake charge",
    weight: 16,
    patterns: [
      /(?:abbuchung|rechnung|transaktion).{0,80}(?:nicht autorisiert|unbekannt|stornieren|widersprechen)/i,
      /(?:cargo|factura|transacci[oó]n).{0,80}(?:no autorizad|desconocid|cancelar|reclamar)/i,
      /(?:d[eé]bit|facture|transaction).{0,80}(?:non autoris[eé]|inconnu|annuler|contester)/i,
      /(?:afschrijving|factuur|transactie).{0,80}(?:niet geautoriseerd|onbekend|annuleren|betwisten)/i,
      /(?:tere[cć]enje|ra[cč]un|transakcij).{0,80}(?:neovla[sš]ten|nepoznat|otka[zž]|ospor)/i,
    ],
  },
  {
    type: "Account takeover / phishing",
    weight: 15,
    patterns: [
      /(?:anmeldedaten|credenciales|identifiants|inloggegevens|podaci za prijavu).{0,55}(?:best[aä]tigen|verificar|confirmer|bevestigen|potvrditi|proveriti)/i,
      /(?:sicherheitswarnung|alerta de seguridad|alerte de s[eé]curit[eé]|beveiligingswaarschuwing|sigurnosno upozorenje|bezbednosno upozorenje).{0,80}(?:konto|cuenta|compte|rekening|ra[cč]un|nalog)/i,
    ],
  },
  {
    type: "Delivery / postal scam",
    weight: 13,
    patterns: [
      /(?:zustellung|entrega|livraison|bezorging|isporuka).{0,90}(?:fehlgeschlagen|fallad[oa]|[eé]chou[eé]e|mislukt|neuspjel|neuspel)/i,
      /(?:zoll|aduana|douane|carina).{0,45}(?:geb[uü]hr|tarifa|frais|kosten|naknad|uplata)/i,
    ],
  },
  {
    type: "Investment / crypto scam",
    weight: 15,
    patterns: [
      /(?:auszahlung|retiro|retrait|opname|isplata).{0,100}(?:geb[uü]hr|tarifa|frais|kosten|naknad|porez|steuer|impuesto|belasting)/i,
      /(?:investition|inversi[oó]n|investissement|investering|ulaganje).{0,80}(?:garantiert|garantizad|garanti|gegarandeerd|zagarantovan|bez rizika)/i,
    ],
  },
  {
    type: "Prize / advance-fee scam",
    weight: 14,
    patterns: [
      /(?:lotterie|loter[ií]a|loterie|loterij|lutrija).{0,90}(?:gewonnen|ganad|gagn[eé]|dobit|osvoj)/i,
      /(?:bearbeitungsgeb[uü]hr|gastos de tramitaci[oó]n|frais de dossier|administratiekosten|tro[sš]kovi obrade).{0,70}(?:preis|premio|prix|prijs|nagrad|dobit)/i,
    ],
  },
  {
    type: "Job scam",
    weight: 12,
    patterns: [
      /(?:stellenangebot|oferta de trabajo|offre d['’]emploi|vacature|ponuda za posao).{0,120}(?:vorauszahlung|pago previo|paiement anticip[eé]|vooraf betalen|uplati unaprijed|uplati unapred)/i,
      /(?:telegram|whatsapp).{0,80}(?:interview|vorstellungsgespr[aä]ch|entrevista|entretien|sollicitatie|razgovor za posao)/i,
    ],
  },
  {
    type: "Tech support scam",
    weight: 14,
    patterns: [
      /(?:rufen sie|llame|appelez|bel).{0,30}(?:microsoft|support|soporte|assistance|helpdesk).{0,35}(?:sofort|ahora|imm[eé]diatement|meteen)/i,
      /(?:instalirajte|instaliraj).{0,30}(?:anydesk|teamviewer|udaljeni pristup|daljinski pristup)/i,
    ],
  },
  {
    type: "Marketplace / payment scam",
    weight: 15,
    patterns: [
      /(?:verk[aä]ufer|vendedor|vendeur|verkoper|prodava[cč]).{0,100}(?:kurier|mensajero|coursier|koerier|dostav)/i,
      /(?:zahlung erhalten|pago recibido|paiement re[cç]u|betaling ontvangen|uplata primljena).{0,100}(?:konto aktualisieren|actualizar la cuenta|mettre [àa] jour le compte|rekening upgraden|nadograditi ra[cč]un)/i,
    ],
  },
  {
    type: "Document / SMS phishing",
    weight: 13,
    patterns: [
      /(?:dokument|rechnung|factura|document|facture|bericht|poruka).{0,80}(?:ausstehend|pendiente|en attente|klaarstaat|na [cč]ekanju)/i,
      /(?:[oö]ffnen sie|abra|ouvrez|open|otvorite).{0,35}(?:dokument|rechnung|factura|document|facture|bericht|poruku).{0,50}(?:link|enlace|lien|poveznic)/i,
    ],
  },
  {
    type: "Romance / impersonation scam",
    weight: 11,
    patterns: [
      /(?:im ausland|en el extranjero|[àa] l['’][eé]tranger|in het buitenland|u inostranstvu).{0,100}(?:geld|dinero|argent|novac|[uü]berweisung|transferencia|virement|overschrijving|uplata)/i,
      /(?:liebling|cari[nñ]o|mon amour|schat|draga|dragi).{0,120}(?:geschenkkarte|tarjeta de regalo|carte cadeau|cadeaukaart|poklon kartic|novac)/i,
    ],
  },
];

const urgencyPatterns = [
  /urgent(?:ly)?/i,
  /immediately/i,
  /within (?:\d+ )?(?:minutes?|hours?)/i,
  /act now/i,
  /hitno/i,
  /odmah/i,
  /u roku od/i,
  /zadnja opomena/i,
  /within \d+ days?/i,
  /within \d+ hours?/i,
  /today/i,
  /right now/i,
  /\bnow\b/i,
  /don['’]t miss/i,
  /last chance/i,
  /expires? after \d+ (?:seconds?|minutes?)/i,
  /send (?:it|the code) fast/i,
  /will be (?:deleted|frozen|suspended|closed)/i,
  /(?:dringend|sofort|unverz[uü]glich|innerhalb von \d+ (?:minuten|stunden))/i,
  /(?:urgente|inmediatamente|ahora mismo|dentro de \d+ (?:minutos|horas))/i,
  /(?:urgent|imm[ée]diatement|sans d[ée]lai|dans les \d+ (?:minutes|heures))/i,
  /(?:dringend|onmiddellijk|meteen|binnen \d+ (?:minuten|uur))/i,
  /(?:hitno|odmah|smjesta|smesta|u roku od \d+ (?:minuta|sati))/i,
];

const credentialPatterns = [
  /password/i,
  /passcode/i,
  /verification code/i,
  /one[- ]time code/i,
  /login/i,
  /lozink/i,
  /kod za potvrdu/i,
  /prijav/i,
  /bank details/i,
  /payment information/i,
  /(?:einmalcode|einmalpasswort|zugangscode)/i,
  /(?:c[oó]digo de un solo uso|c[oó]digo de acceso)/i,
  /(?:code [àa] usage unique|code d['’]acc[eè]s)/i,
  /(?:eenmalige code|toegangscode)/i,
  /(?:jednokratni kod|pristupni podaci|podaci za prijavu)/i,
  /card (?:number|details|information)/i,
  /security (?:code|question)/i,
  /social security/i,
  /(?:unlock|verification|security).{0,20}code/i,
  /(?:send|share|tell).{0,25}(?:me )?(?:the |your )?(?:code|otp)/i,
  /(?:government-issued|government issued|photo id|passport|national id|proof of address)/i,
  /(?:passwort|kennwort|anmeldedaten|sicherheitscode|tan[- ]?code)/i,
  /(?:contrase[nñ]a|credenciales|inicio de sesi[oó]n|c[oó]digo de verificaci[oó]n)/i,
  /(?:mot de passe|identifiants|connexion|code de v[ée]rification)/i,
  /(?:wachtwoord|inloggegevens|aanmelden|verificatiecode)/i,
  /(?:lozinka|lozinku|podaci za prijavu|verifikacijski kod|sigurnosni kod)/i,
];

const credentialRequestPatterns = [
  /(?:send|share|tell|provide|enter|submit|type|confirm|verify|update).{0,45}(?:your\s+)?(?:password|passcode|verification code|one[- ]time code|otp|login details|bank details|card (?:number|details)|security code)/i,
  /(?:password|passcode|verification code|one[- ]time code|otp|login details|bank details|security code).{0,45}(?:send|share|provide|reply|message|tell)/i,
  /(?:upload|send|submit|provide).{0,45}(?:government-issued|government issued|photo id|passport|national id|proof of address)/i,
  /(?:senden|teilen|eingeben|best[aä]tigen|verifizieren|aktualisieren).{0,45}(?:passwort|kennwort|anmeldedaten|sicherheitscode|tan[- ]?code)/i,
  /(?:enviar|compartir|introducir|confirmar|verificar|actualizar).{0,45}(?:contraseña|credenciales|código de verificación|código de acceso)/i,
  /(?:envoy(?:ez|er)|partag(?:ez|er)|saisir|confirm(?:ez|er)|v(?:é|e|Ã©)rifi(?:ez|er|e)|mettre (?:à|a|Ã ) jour).{0,45}(?:mot de passe|identifiants|code de v(?:é|e|Ã©)rification|code d['’]acc(?:è|e|Ã¨)s)/i,
  /(?:stuur|deel|voer|bevestig|verifieer|werk bij).{0,45}(?:wachtwoord|inloggegevens|verificatiecode|toegangscode)/i,
  /(?:pošalji|podijeli|podeli|unesi|potvrdi|provjeri|proveri|ažuriraj).{0,45}(?:lozink|zapork|podatke za prijavu|verifikacijski kod|sigurnosni kod|bezbednosni kod|jednokratni kod)/i,
];

const routineAccountNoticePatterns = [
  /(?:an account|your account).{0,35}(?:has been|was|is now).{0,20}(?:created|set up|activated)/i,
  /(?:you can|use the following details to).{0,30}(?:log in|sign in|access)/i,
  /(?:set|create|choose).{0,25}(?:your )?password.{0,30}(?:for the first time|first login|before your first login)/i,
  /(?:this (?:message|email) was|automatically).{0,25}(?:generated|sent)/i,
  /(?:contact|reach).{0,40}(?:support|administrator|clinic|practice).{0,35}(?:questions|help|assistance)/i,
  /(?:konto|account).{0,35}(?:wurde|is).{0,20}(?:erstellt|aangemaakt)/i,
  /(?:cuenta|compte).{0,35}(?:ha sido|a été).{0,20}(?:creada|créé)/i,
  /(?:passwort|wachtwoord|contraseña|mot de passe).{0,35}(?:erstmals|eerste keer|primera vez|première fois)/i,
  /(?:nalog|račun).{0,35}(?:je|vam je).{0,20}(?:kreiran|otvoren|aktiviran)/i,
  /(?:automatisch generiert|automatisch gegenereerd|generado automáticamente|généré automatiquement|automatski generisana|automatski generirana)/i,
];

const paymentPatterns = [
  /gift card/i,
  /wire transfer/i,
  /bank transfer/i,
  /crypto(?:currency)?/i,
  /bitcoin/i,
  /uplati/i,
  /novac/i,
  /naknad/i,
  /kartic/i,
  /\busd\b/i,
  /\busdt\b/i,
  /total due/i,
  /\bdeposit\b/i,
  /payment method/i,
  /withdrawal/i,
  /(?:geld senden|dinero enviar|envoyer de l['’]argent|geld sturen|po[sš]alji novac)/i,
  /(?:bearbeitungsgeb[uü]hr|tarifa de tramitaci[oó]n|frais de traitement|verwerkingskosten|naknada za obradu)/i,
  /hourly rate/i,
  /(?:[uü]berweisung|geschenkkarte|gutschein|zahlung|kryptow[aä]hrung)/i,
  /(?:transferencia|tarjeta de regalo|pago|dep[oó]sito|criptomoneda)/i,
  /(?:virement|carte cadeau|paiement|d[ée]p[oô]t|cryptomonnaie)/i,
  /(?:overschrijving|cadeaukaart|betaling|storting|cryptovaluta)/i,
  /(?:bankovna uplata|poklon kartica|darovna kartica|kripto valuta|depozit)/i,
  /(?:mobile deposit|mobile banking app|paying by check|payment by check)/i,
  /(?:voucher|store card)/i,
];

const consequencePatterns = [
  /suspend(?:ed|ing|sion)?/i,
  /deactivat(?:e|ed|ion)/i,
  /locked/i,
  /frozen/i,
  /deleted/i,
  /account on hold/i,
  /(?:konto|cuenta|compte|rekening|ra[cč]un|nalog).{0,45}(?:abl[aä]uft|caducar[aá]|expirera|verloopt|isti[cč]e)/i,
  /unable to credit/i,
  /payment.{0,25}(?:failed|declined)/i,
  /data.{0,30}(?:lost|deleted|removed)/i,
  /(?:blokiran|zakljucan|zamrznut|obrisan)/i,
  /(?:gesperrt|deaktiviert|eingefroren|gel[oö]scht)/i,
  /(?:bloquead[oa]|suspendid[oa]|desactivad[oa]|eliminad[oa])/i,
  /(?:bloqu[ée]|suspendu|d[ée]sactiv[ée]|supprim[ée])/i,
  /(?:geblokkeerd|opgeschort|gedeactiveerd|verwijderd)/i,
  /(?:zaklju[cč]an|zamrznut|deaktiviran|obrisan)/i,
];

const rewardPatterns = [
  /\bbonus\b/i,
  /giveaway/i,
  /\bprize\b/i,
  /\breward\b/i,
  /guaranteed.{0,20}(?:profit|return|income)/i,
  /earn.{0,20}(?:daily|weekly|per day|\$\s?\d+)/i,
  /paid you/i,
  /(?:garantierter gewinn|beneficio garantizado|b[eé]n[eé]fice garanti|gegarandeerde winst|zagarantovana zarada|zajam[cč]ena zarada)/i,
  /receive.{0,20}\$\s?\d+/i,
  /(?:nagrada|poklon|zarad)/i,
  /(?:gewinn|gewonnen|belohnung|garantierte rendite)/i,
  /(?:premio|ganador|recompensa|rentabilidad garantizada)/i,
  /(?:prix|gagnant|r[ée]compense|rendement garanti)/i,
  /(?:prijs|winnaar|beloning|gegarandeerd rendement)/i,
  /(?:dobitnik|osvojili|zagarantovana zarada|zajam[cč]ena zarada)/i,
];

const callToActionPatterns = [
  /(?:click|visit|access|open|view).{0,30}(?:here|link|site|page|document)/i,
  /(?:update|confirm|verify|enter|submit).{0,35}(?:details|information|account|payment|password|code)/i,
  /(?:reply|respond).{0,25}(?:yes|stop|confirm|link)/i,
  /(?:call|contact|text).{0,25}\d{7,}/i,
  /(?:register|sign up|schedule|book).{0,35}(?:now|here|meeting|account)/i,
  /(?:pay|send|transfer|buy).{0,40}(?:fee|deposit|gift card|crypto|money|half|\$\s?\d+)/i,
  /(?:make|complete).{0,30}(?:mobile deposit|deposit).{0,60}(?:banking app|check)/i,
  /(?:send|share|tell).{0,30}(?:me )?(?:the |your )?(?:code|otp)/i,
  /(?:complete|submit).{0,35}(?:pre-employment verification|identity review|appeal)/i,
  /(?:klicken|[oö]ffnen|best[aä]tigen|bezahlen|senden).{0,45}(?:link|konto|daten|geb[uü]hr|code|zahlung)/i,
  /(?:haga clic|abrir|confirmar|verificar|pagar|enviar).{0,45}(?:enlace|cuenta|datos|tarifa|c[oó]digo|pago)/i,
  /(?:cliquez|ouvrir|confirmer|v[ée]rifier|payer|envoyer).{0,45}(?:lien|compte|donn[ée]es|frais|code|paiement)/i,
  /(?:klik|open|bevestig|verifieer|betaal|stuur).{0,45}(?:link|rekening|gegevens|kosten|code|betaling)/i,
  /(?:klikni|otvori|potvrdi|provjeri|proveri|uplati|po[sš]alji).{0,45}(?:link|nalog|ra[cč]un|podatke|naknadu|kod|uplatu)/i,
];

const impersonationPatterns = [
  /(?:apple|paypal|zelle|microsoft|amazon|netflix|icloud|google|fedex|ups|dhl) (?:account|support|team|payment|security)/i,
  /copyright.{0,50}(?:apple|microsoft|google|amazon)/i,
  /(?:banka|po[sš]ta|policija|porezna uprava).{0,60}(?:nalog|ra[cč]un|uplata|kazna|potvrda)/i,
];

const secrecyPatterns = [
  /(?:do not|don['’]t|never).{0,35}(?:tell|contact|call|inform|share).{0,35}(?:bank|family|police|employer|anyone)/i,
  /(?:keep|this is).{0,25}(?:secret|confidential|between us)/i,
  /(?:move|continue|contact me).{0,40}(?:whatsapp|telegram|signal app|private chat)/i,
  /(?:surprise|keep this between us).{0,120}(?:gift card|store card|voucher|reimburse)/i,
  /(?:ne govori|nemoj re[cć]i|ne kontaktiraj).{0,35}(?:banci|policiji|porodici|nikome)/i,
  /(?:nicht weitersagen|geheim halten|no se lo diga|mant[eé]ngalo en secreto|ne le dites pas|gardez.*secret|vertel het niemand|houd.*geheim)/i,
];

const authorityPatterns = [
  /(?:ceo|director|manager|boss|police|tax office|irs|court|government).{0,90}(?:urgent|transfer|payment|gift card|confidential|warrant|arrest)/i,
  /(?:i am|this is|speaking on behalf of).{0,45}(?:your boss|the ceo|the bank|the police|support|security team)/i,
  /(?:policija|sud|porezna|direktor|šef|sef).{0,80}(?:hitno|uplati|transfer|kazna|uhap|povjerljivo)/i,
  /(?:gesch[aä]ftsf[uü]hrer|direktor|polizei|finanzamt).{0,80}(?:dringend|zahlung|[uü]berweisung|vertraulich)/i,
  /(?:director|polic[ií]a|agencia tributaria).{0,80}(?:urgente|pago|transferencia|confidencial)/i,
  /(?:directeur|police|imp[oô]ts).{0,80}(?:urgent|paiement|virement|confidentiel)/i,
  /(?:directeur|politie|belastingdienst).{0,80}(?:dringend|betaling|overschrijving|vertrouwelijk)/i,
];

const evasionPatterns = [
  /\b(?:p[\s._-]+a[\s._-]+s[\s._-]+s[\s._-]+w[\s._-]+o[\s._-]+r[\s._-]+d|l[\s._-]+o[\s._-]+g[\s._-]+i[\s._-]+n)\b/i,
  /\b(?:b[1!]tcoin|bit\(oin|cr¥pt[0o]|crypt0|g[1!]ft[\s._-]+card|pa¥pal|paypa1)\b/i,
  /[\u200B-\u200D\u2060\uFEFF]/,
];

const benignContextPatterns = [
  /(?:security awareness|training example|phishing simulation|scam example|educational example)/i,
  /(?:do not click|do not reply|never share).{0,80}(?:suspicious|scam|phishing|unknown)/i,
  /(?:reported|marked|identified).{0,30}(?:as )?(?:a )?(?:scam|phishing)/i,
];

const languageProfiles = [
  { label: "English", patterns: [/\b(?:your|account|please|click|payment|verify|message)\b/i, /\b(?:the|this|will|with|from)\b/i] },
  { label: "German", patterns: [/\b(?:ihr|konto|bitte|klicken|zahlung|best[aä]tigen|nachricht)\b/i, /\b(?:dringend|sofort|passwort|daten|[uü]berweisung)\b/i] },
  { label: "Spanish", patterns: [/\b(?:su|cuenta|por favor|haga clic|pago|verificar|mensaje)\b/i, /\b(?:urgente|contrase[nñ]a|datos|transferencia|ahora)\b/i] },
  { label: "French", patterns: [/\b(?:votre|compte|veuillez|cliquez|paiement|v[ée]rifier|message)\b/i, /\b(?:urgent|mot de passe|donn[ée]es|virement|imm[ée]diatement)\b/i] },
  { label: "Dutch", patterns: [/\b(?:uw|rekening|alstublieft|klik|betaling|verifieer|bericht)\b/i, /\b(?:dringend|wachtwoord|gegevens|overschrijving|onmiddellijk)\b/i] },
] as const;

const generalLanguagePatterns: Record<string, RegExp[]> = {
  English: [/\b(?:and|with|from|that|this|please|your|have|will)\b/i],
  German: [/\b(?:und|mit|von|dass|dies|bitte|ihre|haben|wird|nicht)\b/i],
  Spanish: [/\b(?:y|con|desde|que|este|esta|por favor|usted|tiene|ser[aá]|no)\b/i],
  French: [/\b(?:et|avec|depuis|que|ce|cette|veuillez|vous|votre|sera|pas)\b/i],
  Dutch: [/\b(?:en|met|van|dat|dit|deze|alstublieft|heeft|wordt|niet)\b/i],
};

const bhsLanguagePatterns = [
  /\b(?:va[sš]|ra[cč]un|nalog|molimo|kliknite|uplata|potvrdite|poruka)\b/i,
  /\b(?:odmah|hitno|lozink|podatke|po[sš]alj)\w*/i,
  /[čćđšž]/i,
];

const bhsCommonLanguagePatterns = [
  /\b(?:sa|iz|da|ovo|ova|molim|va[sš]|imate|nije|biti|poruka|ra[cč]un|nalog)\b/i,
];

const regionalBhsProfiles = [
  {
    label: "Bosnian",
    patterns: [
      /\b(?:ra[cč]un [cć]e|[cć]e biti blokiran|historij|op[cć]in|lahko)\w*/i,
      /\b(?:saglasnost|li[cč]ni|sljede[cć]|provjer)\w*/i,
    ],
  },
  {
    label: "Croatian",
    patterns: [
      /\bbit [cć]e\b/i,
      /\b(?:poveznic|zapork|tisu[cć]|sije[cč]|tvrtk|osobn|uvjet|povijest|neovisn)\w*/i,
    ],
  },
  {
    label: "Serbian",
    patterns: [
      /[\u0400-\u04ff]/,
      /\b(?:prover|bezbed|slede[cć]|bi[cć]e|nalog|uslov|preduze[cć]|hiljad)\w*/i,
    ],
  },
] as const;

const suspiciousTlds = new Set([
  "zip",
  "mov",
  "click",
  "top",
  "xyz",
  "live",
  "support",
  "work",
  "shop",
  "rest",
  "gq",
  "tk",
]);

const shorteners = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
]);

function jsonResponse(payload: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function cleanMessage(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function isEnabled(value: string | undefined): boolean {
  return value?.toLowerCase() === "true";
}

function getClientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "local";
}

async function getRateKey(request: Request, action: string) {
  return `${await sha256(getClientIp(request))}:${action}`;
}

async function checkRateLimit(
  request: Request,
  env: ScannerEnv,
  action: string,
  limit: number,
  windowSeconds: number,
) {
  const key = await getRateKey(request, action);
  return env.RATE_LIMITER.getByName(key).check(limit, windowSeconds);
}

function rateLimitUnavailable() {
  return jsonResponse(
    { error: "Request protection is temporarily unavailable. Please try again shortly." },
    503,
    { "retry-after": "5" },
  );
}

function rateLimitHeaders(rate: RateLimitDecision) {
  return {
    "x-ratelimit-limit": String(rate.limit),
    "x-ratelimit-remaining": String(rate.remaining),
    "x-ratelimit-reset": String(Math.ceil(rate.resetAt / 1_000)),
  };
}

async function validateTurnstile(request: Request, env: ScannerEnv, token: unknown) {
  const hasSiteKey = Boolean(env.TURNSTILE_SITE_KEY);
  const hasSecret = Boolean(env.TURNSTILE_SECRET_KEY);
  if (!hasSiteKey && !hasSecret) return { valid: true, configured: false, misconfigured: false };
  if (!hasSiteKey || !hasSecret) return { valid: false, configured: true, misconfigured: true };
  if (typeof token !== "string" || !token.trim() || token.length > 2_048) {
    return { valid: false, configured: true, misconfigured: false };
  }

  try {
    const response = await fetchWithTimeout("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: getClientIp(request),
        idempotency_key: crypto.randomUUID(),
      }),
    });
    const result = await readProviderJson(response) as { success?: boolean; hostname?: string; action?: string } | null;
    const expectedHostname = new URL(request.url).hostname;
    return {
      valid: response.ok && result?.success === true && result.hostname === expectedHostname && result.action === TURNSTILE_ACTION,
      configured: true,
      misconfigured: false,
    };
  } catch {
    return { valid: false, configured: true, misconfigured: false };
  }
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isJsonContentType(request: Request) {
  return /^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "");
}

async function readBoundedText(stream: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string | null> {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("body too large").catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

type ParsedJsonObject = { body: Record<string, unknown> | null; response: Response | null };

async function parseJsonObject(request: Request, maxBytes: number): Promise<ParsedJsonObject> {
  if (!isJsonContentType(request)) {
    return { body: null, response: jsonResponse({ error: "Content-Type must be application/json." }, 415) };
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength) {
    const length = Number(declaredLength);
    if (!Number.isFinite(length) || length < 0) {
      return { body: null, response: jsonResponse({ error: "Invalid Content-Length." }, 400) };
    }
    if (length > maxBytes) {
      return { body: null, response: jsonResponse({ error: "Request body is too large." }, 413) };
    }
  }

  const text = await readBoundedText(request.body, maxBytes);
  if (text === null) return { body: null, response: jsonResponse({ error: "Request body is too large or invalid." }, 413) };

  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON object required");
    return { body: value as Record<string, unknown>, response: null };
  } catch {
    return { body: null, response: jsonResponse({ error: "Invalid JSON request." }, 400) };
  }
}

async function readProviderJson(response: Response): Promise<Record<string, unknown> | null> {
  const text = await readBoundedText(response.body, PROVIDER_JSON_LIMIT_BYTES);
  if (text === null) return null;
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function isTrustedWriteRequest(request: Request) {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) return false;
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function parseIpv4(hostname: string): number[] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return null;
  const parts = hostname.split(".").map(Number);
  return parts.every((part) => part >= 0 && part <= 255) ? parts : null;
}

function isPrivateOrReservedAddress(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const ipv4 = parseIpv4(normalized);
  if (ipv4) {
    const [a, b, c] = ipv4;
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && [0, 2].includes(c)) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113);
  }
  if (!normalized.includes(":")) return false;
  if (normalized === "::" || normalized === "::1" || normalized.startsWith("ff")) return true;
  if (/^f[cd]/.test(normalized) || /^fe[89ab]/.test(normalized)) return true;
  const mappedIpv4 = normalized.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  return mappedIpv4 ? isPrivateOrReservedAddress(mappedIpv4) : false;
}

function externalUrlBlockReason(value: string, freshSubmission = false): string | null {
  if (value.length > MAX_URL_LENGTH) return "The URL is too long to process safely.";
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return "A valid HTTP or HTTPS URL is required.";
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return "Only HTTP and HTTPS URLs are supported.";
  if (parsed.username || parsed.password) return "URLs containing embedded usernames or passwords are not sent to external providers.";
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname || hostname.length > 253) return "The URL hostname is invalid.";
  if (hostname === "localhost" || /\.(?:localhost|local|internal|intranet|home|lan|corp)$/i.test(hostname) || isPrivateOrReservedAddress(hostname)) {
    return "Private, local, and reserved network addresses are not sent to external providers.";
  }
  if (freshSubmission) {
    for (const key of parsed.searchParams.keys()) {
      if (/^(?:access_?token|auth|authorization|code|credential|jwt|otp|pass(?:word|code)?|reset(?:_?token)?|session(?:id)?|signature|sig|secret|token)$/i.test(key)) {
        return "This URL appears to contain a sensitive access token or credential in its query parameters.";
      }
    }
  }
  return null;
}

function normalizedProviderUrl(value: string) {
  const parsed = new URL(value);
  parsed.hash = "";
  return parsed.href;
}

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function statusSigningKey(env: ScannerEnv) {
  const source = env.STATUS_SIGNING_KEY ?? env.VIRUSTOTAL_API_KEY;
  if (!source) return null;
  const material = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`scamshield-status-v1:${source}`));
  return crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function createStatusToken(analysisId: string, env: ScannerEnv) {
  const key = await statusSigningKey(env);
  if (!key) return null;
  const expires = Math.floor(Date.now() / 1_000) + STATUS_TOKEN_TTL_SECONDS;
  const payload = `${expires}.${analysisId}`;
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return `${expires}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

async function verifyStatusToken(analysisId: string, token: string, env: ScannerEnv) {
  const [expiresValue, signatureValue, extra] = token.split(".");
  if (!expiresValue || !signatureValue || extra || token.length > 160) return false;
  const expires = Number(expiresValue);
  const now = Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(expires) || expires < now || expires > now + STATUS_TOKEN_TTL_SECONDS + 60) return false;
  const signature = base64UrlToBytes(signatureValue);
  const key = await statusSigningKey(env);
  if (!signature || !key) return false;
  return crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(`${expires}.${analysisId}`));
}

async function cachedResult<T>(
  namespace: string,
  identifier: string,
  ttlSeconds: number,
  producer: () => Promise<T>,
  ctx?: ScannerContext,
  shouldCache: (result: T) => boolean = () => true,
) {
  const cacheStorage = globalThis.caches as CacheStorage & { default?: Cache };
  const cache = cacheStorage?.default;
  if (!cache) return producer();

  const key = new Request(`https://scamshield-cache.invalid/${namespace}/${await sha256(identifier)}`);
  try {
    const cached = await cache.match(key);
    if (cached) return (await cached.json()) as T;
  } catch {
    // Cache failures should never stop a scan.
  }

  const result = await producer();
  if (!shouldCache(result)) return result;
  const cacheWrite = cache.put(
      key,
      new Response(JSON.stringify(result), {
        headers: {
          "content-type": "application/json",
          "cache-control": `public, max-age=${ttlSeconds}`,
        },
      }),
    ).catch(() => undefined);
  if (ctx) ctx.waitUntil(cacheWrite);
  else await cacheWrite;
  return result;
}

function stripTrailingPunctuation(value: string) {
  return value.replace(/[),.;!?\]}>'"]+$/g, "");
}

function extractUrls(message: string) {
  const candidates = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) ?? [];
  const urls: string[] = [];
  for (const candidate of candidates) {
    const cleaned = stripTrailingPunctuation(candidate);
    const withScheme = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
    try {
      const parsed = new URL(withScheme);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) continue;
      parsed.hash = "";
      if (parsed.href.length > MAX_URL_LENGTH) continue;
      if (!urls.includes(parsed.href)) urls.push(parsed.href);
    } catch {
      continue;
    }
    if (urls.length >= MAX_URLS) break;
  }
  return urls;
}

function countPatternMatches(message: string, patterns: RegExp[]) {
  return patterns.reduce((count, pattern) => count + (pattern.test(message) ? 1 : 0), 0);
}

function normalizeForDetection(message: string) {
  const withoutTranslationUi = message
    .split(/\r?\n/)
    .filter((line) => !/^\s*(?:translated:\s*.{1,60}|english|translate can make mistakes(?:,\s*so verify translations)?|original text)\s*$/i.test(line))
    .join("\n");
  const normalized = withoutTranslationUi
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  const deobfuscated = normalized
    .replace(/(?<=\p{L})[._-](?=\p{L})/gu, "")
    .replace(/[＠]/g, "@")
    .replace(/0/g, "o")
    .replace(/[1!|]/g, "i")
    .replace(/3/g, "e")
    .replace(/[4@]/g, "a")
    .replace(/[5$]/g, "s")
    .replace(/7/g, "t");
  return deobfuscated === normalized ? normalized : `${normalized} ${deobfuscated}`;
}

function detectMessageLanguage(message: string) {
  if (countPatternMatches(message, [...bhsLanguagePatterns, ...bhsCommonLanguagePatterns])) {
    const regional = regionalBhsProfiles
      .map((profile) => ({ label: profile.label, hits: countPatternMatches(message, [...profile.patterns]) }))
      .sort((a, b) => b.hits - a.hits);
    if (regional[0]?.hits) return regional[0].label;
    return "Bosnian / Croatian / Serbian";
  }

  const ranked = languageProfiles
    .map((profile) => ({
      label: profile.label,
      hits: countPatternMatches(message, [...profile.patterns, ...(generalLanguagePatterns[profile.label] ?? [])]),
    }))
    .sort((a, b) => b.hits - a.hits);
  return ranked[0]?.hits ? ranked[0].label : "Unknown / mixed";
}

function messageAnalysis(message: string, urls: string[]) {
  const normalizedMessage = normalizeForDetection(message);
  const categoryScores = categoryRules.map((rule) => {
    const hits = countPatternMatches(normalizedMessage, rule.patterns);
    return { type: rule.type, score: hits * rule.weight, hits };
  });
  categoryScores.sort((a, b) => b.score - a.score);

  const urgencyHits = countPatternMatches(normalizedMessage, urgencyPatterns);
  const credentialMentionHits = countPatternMatches(normalizedMessage, credentialPatterns);
  const credentialHits = countPatternMatches(normalizedMessage, credentialRequestPatterns);
  const paymentHits = countPatternMatches(normalizedMessage, paymentPatterns);
  const consequenceHits = countPatternMatches(normalizedMessage, consequencePatterns);
  const rewardHits = countPatternMatches(normalizedMessage, rewardPatterns);
  const callToActionHits = countPatternMatches(normalizedMessage, callToActionPatterns);
  const impersonationHits = countPatternMatches(normalizedMessage, impersonationPatterns);
  const secrecyHits = countPatternMatches(normalizedMessage, secrecyPatterns);
  const authorityHits = countPatternMatches(normalizedMessage, authorityPatterns);
  const evasionHits = countPatternMatches(message, evasionPatterns);
  const benignContextHits = countPatternMatches(normalizedMessage, benignContextPatterns);
  const routineAccountNoticeHits = countPatternMatches(normalizedMessage, routineAccountNoticePatterns);
  const uppercaseWords = message.match(/\b[A-ZČĆŽŠĐ]{4,}\b/g)?.length ?? 0;
  const exclamations = Math.min(3, (message.match(/!/g) ?? []).length);

  let score = urls.length ? 8 : 4;
  score += Math.min(30, categoryScores.reduce((sum, category) => sum + category.score, 0));
  score += Math.min(16, urgencyHits * 8);
  score += Math.min(20, credentialHits * 10);
  score += Math.min(18, paymentHits * 9);
  score += Math.min(16, consequenceHits * 8);
  score += Math.min(14, rewardHits * 7);
  score += Math.min(12, callToActionHits * 4);
  score += Math.min(10, impersonationHits * 5);
  score += Math.min(12, secrecyHits * 6);
  score += Math.min(12, authorityHits * 6);
  score += Math.min(10, evasionHits * 5);
  score += Math.min(4, uppercaseWords);
  score += exclamations * 2;
  const independentSignalGroups = [
    urgencyHits,
    credentialHits,
    paymentHits,
    consequenceHits,
    rewardHits,
    callToActionHits,
    impersonationHits,
    secrecyHits,
    authorityHits,
    evasionHits,
  ].filter((hits) => hits > 0).length;
  const strongestCategoryHits = categoryScores[0]?.hits ?? 0;
  const strongestCategoryType = categoryScores[0]?.type ?? "";
  if (credentialHits && callToActionHits && (urgencyHits || consequenceHits || urls.length)) score += 15;
  if (paymentHits && (secrecyHits || authorityHits || rewardHits)) score += 14;
  if (paymentHits && secrecyHits && authorityHits) score = Math.max(score, 78);
  if (urls.length && (credentialHits || paymentHits) && callToActionHits) score += 10;
  if (evasionHits && independentSignalGroups >= 2) score += 8;
  if (strongestCategoryHits >= 2 && independentSignalGroups >= 3) score = Math.max(score, 76);
  else if (strongestCategoryHits >= 1 && independentSignalGroups >= 3) score = Math.max(score, 62);
  else if (strongestCategoryHits >= 1 && (independentSignalGroups >= 2 || (urls.length > 0 && callToActionHits > 0))) score = Math.max(score, 46);
  else if (independentSignalGroups >= 4) score = Math.max(score, 58);
  if (
    strongestCategoryHits >= 2
    && ["Check / mobile-deposit scam", "Identity / verification phishing", "Gift-card impersonation scam", "Verification-code theft"].includes(strongestCategoryType)
  ) {
    score = Math.max(score, 78);
  }
  if (strongestCategoryType === "Delivery / postal scam" && strongestCategoryHits >= 2 && paymentHits) {
    score = Math.max(score, 68);
  }
  const routineAccountNotice = routineAccountNoticeHits >= 2
    && urgencyHits === 0
    && credentialHits === 0
    && paymentHits === 0
    && consequenceHits === 0
    && rewardHits === 0
    && secrecyHits === 0
    && authorityHits === 0
    && evasionHits === 0;
  if (routineAccountNotice) {
    score = Math.max(urls.length ? 8 : 4, score - Math.min(32, routineAccountNoticeHits * 8));
  }
  if (benignContextHits && !callToActionHits && !paymentHits && !credentialHits && !urls.length) {
    score = Math.max(2, score - 22);
  }

  const reasons: string[] = [];
  if (routineAccountNotice) {
    reasons.push("The wording is consistent with a routine account-onboarding notice and does not ask the recipient to disclose credentials.");
  }
  if (categoryScores[0]?.hits) reasons.push(`The wording matches a common ${categoryScores[0].type.toLowerCase()} pattern.`);
  if (urgencyHits) reasons.push("The message creates urgency or a short deadline to reduce careful checking.");
  if (credentialHits) reasons.push("It asks for login, verification, or other sensitive account information.");
  if (paymentHits) reasons.push("It mentions a payment method or transfer commonly abused in scams.");
  if (consequenceHits) reasons.push("It threatens account restrictions, data loss, or another consequence to pressure the recipient.");
  if (rewardHits) reasons.push("It uses a reward, payout, guaranteed return, or unusually attractive offer as a lure.");
  if (callToActionHits && !routineAccountNotice) reasons.push("It pushes the recipient toward an immediate reply, call, payment, registration, or linked page.");
  if (impersonationHits) reasons.push("The wording imitates a recognizable company or official support team.");
  if (secrecyHits) reasons.push("It tries to isolate the recipient or move the conversation away from trusted verification channels.");
  if (authorityHits) reasons.push("It invokes authority or workplace hierarchy to make an unusual request feel mandatory.");
  if (evasionHits) reasons.push("The wording appears intentionally obfuscated to evade ordinary security filters.");
  if (uppercaseWords || exclamations >= 2) reasons.push("The formatting uses pressure signals such as capitals or repeated exclamation marks.");
  if (urls.length) reasons.push(`${urls.length} link${urls.length === 1 ? " was" : "s were"} found and checked separately.`);

  if (!reasons.length) reasons.push("No strong social-engineering pattern was found in the supplied text.");
  const signals = [
    {
      name: "Urgency & pressure",
      count: urgencyHits,
      state: urgencyHits >= 2 ? "danger" : urgencyHits === 1 ? "warning" : "clear",
      detail: urgencyHits
        ? `${urgencyHits} urgency pattern${urgencyHits === 1 ? " was" : "s were"} detected.`
        : "No forced deadline or urgency phrase was detected.",
    },
    {
      name: "Sensitive information",
      count: credentialHits,
      state: credentialHits > 0 ? "danger" : "clear",
      detail: credentialHits
        ? `${credentialHits} request${credentialHits === 1 ? "" : "s"} related to login, identity, or verification data were detected.`
        : credentialMentionHits
          ? `Credential-related terms were mentioned ${credentialMentionHits} time${credentialMentionHits === 1 ? "" : "s"}, but no request to disclose them was detected.`
          : "No request for passwords, login details, or verification codes was detected.",
    },
    {
      name: "Payment language",
      count: paymentHits,
      state: paymentHits >= 2 ? "danger" : paymentHits === 1 ? "warning" : "clear",
      detail: paymentHits
        ? `${paymentHits} payment or transfer signal${paymentHits === 1 ? " was" : "s were"} detected.`
        : "No common payment-pressure phrase was detected.",
    },
    {
      name: "Aggressive formatting",
      count: uppercaseWords + exclamations,
      state: uppercaseWords + exclamations >= 4 ? "warning" : "clear",
      detail: uppercaseWords || exclamations
        ? `${uppercaseWords} uppercase word${uppercaseWords === 1 ? "" : "s"} and ${exclamations} emphasized exclamation mark${exclamations === 1 ? "" : "s"} were counted.`
        : "No strong formatting-pressure signal was detected.",
    },
    {
      name: "Threatened consequences",
      count: consequenceHits,
      state: consequenceHits >= 2 ? "danger" : consequenceHits === 1 ? "warning" : "clear",
      detail: consequenceHits
        ? `${consequenceHits} threat of account restriction, failed payment, or data loss was detected.`
        : "No threat of suspension, freezing, deletion, or failed credit was detected.",
    },
    {
      name: "Reward or profit lure",
      count: rewardHits,
      state: rewardHits >= 2 ? "danger" : rewardHits === 1 ? "warning" : "clear",
      detail: rewardHits
        ? `${rewardHits} reward, payout, bonus, or profit lure was detected.`
        : "No prize, bonus, guaranteed profit, or unexpected payout was detected.",
    },
    {
      name: "Forced call to action",
      count: callToActionHits,
      state: routineAccountNotice ? "clear" : callToActionHits >= 2 ? "danger" : callToActionHits === 1 ? "warning" : "clear",
      detail: routineAccountNotice && callToActionHits
        ? "A first-time account-access instruction was found without urgency, payment pressure, or a request to disclose credentials."
        : callToActionHits
          ? `${callToActionHits} instruction to call, reply, register, pay, or open a link was detected.`
        : "No suspicious instruction to reply, call, register, pay, or open a link was detected.",
    },
    {
      name: "Brand impersonation",
      count: impersonationHits,
      state: impersonationHits >= 2 ? "danger" : impersonationHits === 1 ? "warning" : "clear",
      detail: impersonationHits
        ? `${impersonationHits} phrase associated with brand or support-team impersonation was detected.`
        : "No strong brand or official-support impersonation phrase was detected.",
    },
    {
      name: "Secrecy & isolation",
      count: secrecyHits,
      state: secrecyHits > 0 ? "danger" : "clear",
      detail: secrecyHits
        ? `${secrecyHits} instruction${secrecyHits === 1 ? "" : "s"} to hide the request or leave trusted channels were detected.`
        : "No instruction to keep the request secret or avoid trusted contacts was detected.",
    },
    {
      name: "Authority pressure",
      count: authorityHits,
      state: authorityHits > 0 ? "warning" : "clear",
      detail: authorityHits
        ? `${authorityHits} authority or workplace-pressure pattern${authorityHits === 1 ? " was" : "s were"} detected.`
        : "No unusual request backed by authority or workplace hierarchy was detected.",
    },
    {
      name: "Filter evasion",
      count: evasionHits,
      state: evasionHits > 0 ? "warning" : "clear",
      detail: evasionHits
        ? `${evasionHits} obfuscation pattern${evasionHits === 1 ? " was" : "s were"} detected.`
        : "No deliberate word or character obfuscation was detected.",
    },
  ] as const;

  const strongestCategory = categoryScores[0]?.hits ? categoryScores[0].type : null;
  const inferredType = credentialHits && (urgencyHits || consequenceHits || urls.length)
    ? "Credential phishing / account takeover"
    : paymentHits && (urgencyHits || consequenceHits)
      ? "Payment-pressure / advance-fee scam"
      : authorityHits && paymentHits
        ? "Authority impersonation / payment fraud"
        : rewardHits && paymentHits
          ? "Reward / payment scam"
          : impersonationHits && (callToActionHits || urls.length)
            ? "Brand impersonation / social engineering"
            : urls.length && callToActionHits
              ? "Suspicious link solicitation"
              : urgencyHits || consequenceHits
                ? "Social-engineering pressure"
                : "No specific scam category identified";

  const words = message.match(/\S+/g)?.length ?? 0;
  const lines = message ? message.split(/\r?\n/).length : 0;
  return {
    score: Math.min(96, score),
    scamType: routineAccountNotice ? "Routine account onboarding / access notice" : strongestCategory ?? inferredType,
    reasons,
    indicators: { urgency: urgencyHits, credentials: credentialHits, payment: paymentHits },
    signals,
    categories: categoryScores.filter((category) => category.hits > 0).slice(0, 4),
    context: { routineAccountNotice, routineAccountNoticeHits, credentialMentionHits },
    stats: {
      characters: message.length,
      words,
      lines,
      uppercaseWords,
      exclamations,
    },
    detectedLanguage: detectMessageLanguage(normalizedMessage),
  };
}

function inspectUrl(url: string) {
  const parsed = new URL(url);
  const domain = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const reasons: string[] = [];
  let score = 8;

  const tld = domain.split(".").pop() ?? "";
  if (suspiciousTlds.has(tld)) {
    score += 18;
    reasons.push(`The .${tld} top-level domain is frequently used in disposable or high-risk campaigns.`);
  }
  if (shorteners.has(domain)) {
    score += 20;
    reasons.push("A link shortener hides the final destination.");
  }
  const isIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain);
  if (isIpAddress) {
    score += 28;
    reasons.push("The link uses a raw IP address instead of a normal domain name.");
  }
  const isPunycode = domain.split(".").some((label) => label.startsWith("xn--"));
  if (isPunycode) {
    score += 25;
    reasons.push("The domain uses Punycode and may imitate another brand with look-alike characters.");
  }
  if (/[A-Z]/.test(parsed.hostname) || /paypa[i1l]|micr[o0]soft|app[l1]e|g[o0]{2}gle/i.test(parsed.hostname)) {
    score += 22;
    reasons.push("The hostname contains a possible brand look-alike or character substitution.");
  }
  const riskyWords = domain.match(/login|verify|secure|account|support|wallet|bonus|claim|update|signin/gi)?.length ?? 0;
  if (riskyWords) {
    score += Math.min(22, riskyWords * 8);
    reasons.push("The domain uses trust or account-related words often seen in phishing links.");
  }
  const hyphens = (domain.match(/-/g) ?? []).length;
  if (hyphens >= 2) {
    score += Math.min(14, hyphens * 4);
    reasons.push("The hostname contains several hyphens, which can be used to mimic a legitimate service.");
  }
  if (domain.length > 42) {
    score += 10;
    reasons.push("The hostname is unusually long.");
  }
  if (parsed.username || parsed.password || url.includes("@")) {
    score += 24;
    reasons.push("The URL contains user-info syntax that can disguise the real destination.");
  }
  if (!reasons.length) reasons.push("No obvious structural red flags were found in the URL itself.");
  return {
    domain,
    score: Math.min(92, score),
    reasons,
    technical: {
      protocol: parsed.protocol === "https:" ? "HTTPS" as const : "HTTP" as const,
      tld,
      usesHttps: parsed.protocol === "https:",
      isIpAddress,
      isPunycode,
      isShortener: shorteners.has(domain),
      hasUserInfo: Boolean(parsed.username || parsed.password || url.includes("@")),
      hostnameLength: domain.length,
      pathDepth: parsed.pathname.split("/").filter(Boolean).length,
      queryParameters: [...parsed.searchParams].length,
    },
  };
}

function unavailableProvider(name: string, detail: string, configured = false): ProviderResult {
  return { name, state: "unavailable", label: configured ? "Unavailable" : "Not configured", detail, configured };
}

async function googleSafeBrowsing(url: string, env: ScannerEnv, ctx?: ScannerContext): Promise<ProviderResult> {
  const apiKey = env.GOOGLE_API_KEY;
  if (!apiKey) {
    return unavailableProvider("Google Safe Browsing", "Add GOOGLE_API_KEY to enable live threat-list checks.");
  }
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return { name: "Google Safe Browsing", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true };
  }

  return cachedResult("gsb-v5", url, 300, async () => {
    try {
      const endpoint = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
      endpoint.searchParams.append("urls", url);
      const response = await fetchWithTimeout(endpoint, {
        headers: {
          accept: "application/json",
          "x-goog-api-key": apiKey,
        },
      });
      if (!response.ok) {
        return unavailableProvider("Google Safe Browsing", `The provider returned HTTP ${response.status}.`, true);
      }
      const data = await readProviderJson(response);
      const flagged = Array.isArray(data?.threats) && data.threats.length > 0;
      return flagged
        ? { name: "Google Safe Browsing", state: "danger", label: "Threat match", detail: "Google Safe Browsing lists this URL as a known threat.", configured: true }
        : { name: "Google Safe Browsing", state: "clear", label: "No match", detail: "No current Google Safe Browsing threat-list match was returned.", configured: true };
    } catch {
      return unavailableProvider("Google Safe Browsing", "The check timed out or could not be reached.", true);
    }
  }, ctx);
}

const commonCountryCodeSecondLevels = new Set(["ac", "co", "com", "edu", "gov", "net", "org"]);

function rdapDomainCandidates(domain: string) {
  const labels = domain.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return [labels.join(".")];

  const countryCodeSuffix = labels.at(-1)?.length === 2 && commonCountryCodeSecondLevels.has(labels.at(-2) ?? "");
  const minimumLabels = countryCodeSuffix ? 3 : 2;
  const firstStart = Math.max(0, labels.length - (minimumLabels + 3));
  const candidates: string[] = [];
  for (let start = firstStart; labels.length - start >= minimumLabels; start += 1) {
    candidates.push(labels.slice(start).join("."));
  }
  return candidates;
}

function safeRdapServiceBase(value: unknown) {
  if (typeof value !== "string") return null;
  try {
    const endpoint = new URL(value);
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || externalUrlBlockReason(endpoint.href)) return null;
    endpoint.search = "";
    endpoint.hash = "";
    if (!endpoint.pathname.endsWith("/")) endpoint.pathname += "/";
    return endpoint.href;
  } catch {
    return null;
  }
}

async function rdapServiceUrls(domain: string, ctx?: ScannerContext) {
  const tld = domain.toLowerCase().replace(/\.$/, "").split(".").at(-1) ?? "";
  const discovered: string[] = [];
  try {
    const bootstrap = await cachedResult<Record<string, unknown> | null>(
      "rdap-bootstrap-v1",
      "dns",
      86_400,
      async () => {
        const response = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", {
          headers: { accept: "application/json" },
        }, 3_500);
        if (!response.ok) return null;
        return readProviderJson(response);
      },
      ctx,
      (result) => result !== null,
    );
    const services = Array.isArray(bootstrap?.services) ? bootstrap.services : [];
    for (const entry of services) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const suffixes = Array.isArray(entry[0]) ? entry[0] : [];
      if (!suffixes.some((suffix) => String(suffix).toLowerCase() === tld)) continue;
      const urls = Array.isArray(entry[1]) ? entry[1] : [];
      for (const value of urls) {
        const service = safeRdapServiceBase(value);
        if (service && !discovered.includes(service)) discovered.push(service);
      }
    }
  } catch {
    // rdap.org remains available as a standards-based bootstrap fallback.
  }
  discovered.push("https://rdap.org/");
  return [...new Set(discovered)];
}

async function rdapDomainAge(domain: string, env: ScannerEnv, ctx?: ScannerContext): Promise<{ provider: ProviderResult; ageDays: number | null; riskBoost: number }> {
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return {
      provider: { name: "RDAP domain age", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true },
      ageDays: 3_650,
      riskBoost: 0,
    };
  }

  return cachedResult("rdap-age-v2", domain, 86_400, async () => {
    try {
      const services = await rdapServiceUrls(domain, ctx);
      const candidates = rdapDomainCandidates(domain);
      let data: Record<string, unknown> | null = null;
      let foundResponse = false;
      const notFoundCandidates = new Set<string>();

      for (const candidate of candidates) {
        for (const service of services) {
          try {
            const endpoint = new URL(`domain/${encodeURIComponent(candidate)}`, service);
            const response = await fetchWithTimeout(endpoint, {
              headers: { accept: "application/rdap+json, application/json" },
              redirect: "follow",
            }, 5_500);
            if (response.status === 404) {
              notFoundCandidates.add(candidate);
              continue;
            }
            if (!response.ok) continue;
            data = await readProviderJson(response);
            if (data) {
              foundResponse = true;
              break;
            }
          } catch {
            // Try another authoritative service or the rdap.org bootstrap fallback.
          }
        }
        if (foundResponse) break;
      }

      if (!foundResponse || !data) {
        if (notFoundCandidates.size !== candidates.length) throw new Error("rdap unavailable");
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "No record", detail: "No public RDAP registration record was found for this domain.", configured: true },
          ageDays: null,
          riskBoost: 16,
        };
      }
      const events = Array.isArray(data?.events) ? data.events : [];
      const registration = events.find((event): event is { eventAction?: string; eventDate?: string } =>
        Boolean(event && typeof event === "object" && /^(?:registration|registered|creation|created)$/i.test(String((event as Record<string, unknown>).eventAction ?? ""))),
      );
      const registrationTime = Date.parse(registration?.eventDate ?? "");
      if (!Number.isFinite(registrationTime) || registrationTime > Date.now() + 86_400_000) {
        return {
          provider: { name: "RDAP domain age", state: "unavailable", label: "Unknown", detail: "The registration record does not publish a creation date.", configured: true },
          ageDays: null,
          riskBoost: 4,
        };
      }
      const ageDays = Math.max(0, Math.floor((Date.now() - registrationTime) / 86_400_000));
      if (ageDays < 30) {
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "Very new", detail: `The domain was registered about ${ageDays} day${ageDays === 1 ? "" : "s"} ago.`, configured: true },
          ageDays,
          riskBoost: 24,
        };
      }
      if (ageDays < 180) {
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "New domain", detail: `The domain is about ${ageDays} days old.`, configured: true },
          ageDays,
          riskBoost: 12,
        };
      }
      return {
        provider: { name: "RDAP domain age", state: "clear", label: "Established", detail: `The domain is about ${ageDays} days old. Age alone does not prove safety.`, configured: true },
        ageDays,
        riskBoost: 0,
      };
    } catch {
      return { provider: unavailableProvider("RDAP domain age", "The registration lookup timed out or was unavailable.", true), ageDays: null, riskBoost: 0 };
    }
  }, ctx, (result) => result.provider.label !== "Unavailable");
}

function base64Url(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function vtVerdict(stats: Record<string, number> | null) {
  const malicious = stats?.malicious ?? 0;
  const suspicious = stats?.suspicious ?? 0;
  if (malicious > 0) return { state: "danger" as const, label: `${malicious} malicious`, boost: 94 };
  if (suspicious > 0) return { state: "warning" as const, label: `${suspicious} suspicious`, boost: 72 };
  return { state: "clear" as const, label: "No detections", boost: 0 };
}

async function virusTotalExisting(url: string, env: ScannerEnv, ctx?: ScannerContext): Promise<{ provider: ProviderResult; report: LinkReport["virusTotal"]; riskBoost: number }> {
  if (!env.VIRUSTOTAL_API_KEY) {
    return { provider: unavailableProvider("VirusTotal", "Add VIRUSTOTAL_API_KEY to enable reputation and fresh-analysis checks."), report: null, riskBoost: 0 };
  }
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return {
      provider: { name: "VirusTotal", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true },
      report: { found: false, stats: null, lastAnalysisDate: null },
      riskBoost: 0,
    };
  }

  return cachedResult("vt-existing", url, 180, async () => {
    try {
      const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${base64Url(url)}`, {
        headers: { "x-apikey": env.VIRUSTOTAL_API_KEY ?? "", accept: "application/json" },
      });
      if (response.status === 404) {
        return {
          provider: { name: "VirusTotal", state: "not-run", label: "No report", detail: "VirusTotal has no existing report for this exact URL. A new analysis requires your consent.", configured: true },
          report: { found: false, stats: null, lastAnalysisDate: null },
          riskBoost: 0,
        };
      }
      if (!response.ok) {
        return { provider: unavailableProvider("VirusTotal", `The provider returned HTTP ${response.status}.`, true), report: null, riskBoost: 0 };
      }
      const data = await readProviderJson(response) as {
        data?: { attributes?: { last_analysis_stats?: Record<string, number>; last_analysis_date?: number } };
      } | null;
      const stats = data?.data?.attributes?.last_analysis_stats ?? null;
      const lastAnalysisDate = data?.data?.attributes?.last_analysis_date ?? null;
      const verdict = vtVerdict(stats);
      const engines = stats ? Object.values(stats).reduce((sum, count) => sum + count, 0) : 0;
      return {
        provider: {
          name: "VirusTotal",
          state: verdict.state,
          label: verdict.label,
          detail: stats
            ? `Existing report: ${stats.malicious ?? 0} malicious, ${stats.suspicious ?? 0} suspicious, ${stats.harmless ?? 0} harmless, and ${stats.undetected ?? 0} undetected verdicts across ${engines} engines.`
            : "An existing object was found, but it contains no current engine summary.",
          configured: true,
        },
        report: { found: true, stats, lastAnalysisDate },
        riskBoost: verdict.boost,
      };
    } catch {
      return { provider: unavailableProvider("VirusTotal", "The existing-report check timed out or was unavailable.", true), report: null, riskBoost: 0 };
    }
  }, ctx);
}

async function analyzeLink(url: string, mode: "quick" | "deep", env: ScannerEnv, ctx?: ScannerContext): Promise<LinkReport> {
  const providerUrl = normalizedProviderUrl(url);
  const structural = inspectUrl(providerUrl);
  const externalBlock = externalUrlBlockReason(providerUrl);
  if (externalBlock) {
    const domainIntel = await analyzeDomainIntelligence(providerUrl, mode, {
      externalDisabled: isEnabled(env.DISABLE_EXTERNAL_CHECKS),
      protectedReason: externalBlock,
      ctx,
    });
    return {
      url: providerUrl,
      domain: structural.domain,
      riskScore: Math.min(99, Math.max(structural.score, 34)),
      reasons: [externalBlock, ...structural.reasons].slice(0, 7),
      providers: [
        { name: "Google Safe Browsing", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.GOOGLE_API_KEY) },
        { name: "RDAP domain age", state: "not-run", label: "Protected", detail: externalBlock, configured: true },
        { name: "VirusTotal", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.VIRUSTOTAL_API_KEY) },
        ...domainIntel.providers,
      ],
      domainAgeDays: null,
      virusTotal: null,
      domainIntelligence: domainIntel.intelligence,
      technical: structural.technical,
    };
  }
  const [google, rdap, vt, domainIntel] = await Promise.all([
    googleSafeBrowsing(providerUrl, env, ctx),
    rdapDomainAge(structural.domain, env, ctx),
    mode === "deep"
      ? virusTotalExisting(providerUrl, env, ctx)
      : Promise.resolve({
          provider: { name: "VirusTotal", state: "not-run" as const, label: "Deep Scan only", detail: "Run Deep Scan to check the latest existing VirusTotal report.", configured: Boolean(env.VIRUSTOTAL_API_KEY) },
          report: null,
          riskBoost: 0,
        }),
    analyzeDomainIntelligence(providerUrl, mode, {
      externalDisabled: isEnabled(env.DISABLE_EXTERNAL_CHECKS),
      ctx,
    }),
  ]);

  let riskScore = structural.score + rdap.riskBoost + domainIntel.riskBoost;
  if (google.state === "danger") riskScore = Math.max(riskScore, 94);
  riskScore = Math.max(riskScore, vt.riskBoost);
  riskScore = Math.max(riskScore, domainIntel.riskFloor);
  const reasons = [...structural.reasons];
  if (google.state === "danger") reasons.unshift("Google Safe Browsing returned a known-threat match.");
  if (rdap.riskBoost >= 12) reasons.push(rdap.provider.detail);
  if (vt.riskBoost >= 72) reasons.unshift(vt.provider.detail);
  reasons.unshift(...domainIntel.reasons);

  return {
    url: providerUrl,
    domain: structural.domain,
    riskScore: Math.min(99, riskScore),
    reasons: reasons.slice(0, 7),
    providers: [google, rdap.provider, vt.provider, ...domainIntel.providers],
    domainAgeDays: rdap.ageDays,
    virusTotal: vt.report,
    domainIntelligence: domainIntel.intelligence,
    technical: structural.technical,
  };
}

function riskLevel(score: number): RiskLevel {
  if (score >= 67) return "High";
  if (score >= 34) return "Medium";
  return "Low";
}

function recommendedActions(level: RiskLevel) {
  if (level === "High") {
    return [
      "Do not click links, reply, pay, or share login codes.",
      "Verify the request through an official app, saved bookmark, or independently found phone number.",
      "Report the message to the platform, your organization, or the relevant national cybercrime channel.",
    ];
  }
  if (level === "Medium") {
    return [
      "Pause before interacting with the sender or link.",
      "Confirm the request through a separate, trusted communication channel.",
      "Avoid sharing credentials, identity documents, payment details, or verification codes.",
    ];
  }
  return [
    "Use the service through its official app or a saved bookmark when possible.",
    "Stay cautious if the sender later introduces urgency, payment, or credential requests.",
    "Treat this result as guidance, not a guarantee of safety.",
  ];
}

function extractIocs(message: string, urls: string[]) {
  const domains = [...new Set(urls.map((url) => new URL(url).hostname.toLowerCase()))];
  const emails = [...new Set(message.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi) ?? [])];
  const phones = [...new Set(message.match(/\+?\d[\d\s().-]{7,}\d/g) ?? [])].slice(0, 8);
  const cryptoWallets = [...new Set(message.match(/\b(?:bc1[a-z0-9]{25,62}|0x[a-f0-9]{40})\b/gi) ?? [])];
  return { urls, domains, emails, phones, cryptoWallets };
}

async function runScan(message: string, mode: "quick" | "deep", env: ScannerEnv, ctx?: ScannerContext) {
  const scanStartedAt = performance.now();
  const urls = extractUrls(message);
  const local = messageAnalysis(message, urls);
  const localAnalysisMs = Math.round(performance.now() - scanStartedAt);
  const liveChecksStartedAt = performance.now();
  const links = await Promise.all(urls.map((url) => analyzeLink(url, mode, env, ctx)));
  const liveChecksMs = Math.round(performance.now() - liveChecksStartedAt);

  const maxLinkRisk = links.reduce((max, link) => Math.max(max, link.riskScore), 0);
  const blendedRisk = Math.round(local.score * (links.length ? 0.64 : 1) + maxLinkRisk * (links.length ? 0.36 : 0));
  let riskPercent = Math.max(local.score, maxLinkRisk, blendedRisk);
  if (links.length && local.indicators.urgency > 0 && local.indicators.credentials > 0) {
    riskPercent = Math.max(riskPercent, 76);
  } else if (links.length && local.indicators.credentials > 0 && maxLinkRisk >= 34) {
    riskPercent = Math.max(riskPercent, 68);
  }
  if (links.some((link) => link.providers.some((provider) => provider.state === "danger"))) {
    riskPercent = Math.max(riskPercent, 90);
  }
  riskPercent = Math.min(99, riskPercent);
  const level = riskLevel(riskPercent);

  const providerThreatReasons = links.flatMap((link) =>
    link.reasons.filter((reason) => /Google Safe Browsing|VirusTotal/i.test(reason)),
  );
  const structuralReasons = links.flatMap((link) =>
    link.reasons.filter((reason) => !/No obvious structural|Google Safe Browsing|VirusTotal/i.test(reason)),
  );
  const combinedReasons = [...providerThreatReasons, ...local.reasons, ...structuralReasons];
  const reasons = [...new Set(combinedReasons)].slice(0, 6);
  while (reasons.length < 3) {
    reasons.push(
      reasons.length === 1
        ? "No live reputation provider returned a confirmed threat match."
        : "A clean result cannot prove that a sender or link is trustworthy.",
    );
  }

  const providers = links.length
    ? links.flatMap((link) => link.providers.map((provider) => ({ ...provider, subject: link.domain })))
    : [
        { name: "Google Safe Browsing", state: "not-run", label: "No URL", detail: "No URL was found in the supplied text.", configured: Boolean(env.GOOGLE_API_KEY), subject: "Message only" },
        { name: "RDAP domain age", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        {
          name: "VirusTotal",
          state: "not-run",
          label: "No URL",
          detail: "VirusTotal analyzes URLs, and this input contains no link.",
          configured: Boolean(env.VIRUSTOTAL_API_KEY),
          subject: "Message only",
        },
        { name: "Brand similarity", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "DNS footprint", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "Certificate Transparency", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "Redirect path", state: "not-run", label: "No URL", detail: "No URL was found in the supplied text.", configured: true, subject: "Message only" },
      ];

  const providerCoverage = {
    total: providers.length,
    completed: providers.filter((provider) => ["clear", "warning", "danger"].includes(provider.state)).length,
    threats: providers.filter((provider) => provider.state === "danger").length,
    warnings: providers.filter((provider) => provider.state === "warning").length,
    unavailable: providers.filter((provider) => provider.state === "unavailable").length,
    notRun: providers.filter((provider) => provider.state === "not-run").length,
  };
  const messageWithoutUrls = urls.reduce((value, url) => value.replace(url, ""), message).trim();

  return {
    scanMode: mode,
    scannedAt: new Date().toISOString(),
    riskPercent,
    riskLevel: level,
    riskLabel: level === "High" ? "Likely dangerous" : level === "Medium" ? "Needs verification" : "No strong threat found",
    scamType: local.scamType,
    reasons,
    actions: recommendedActions(level),
    evidence: [
      ...local.reasons.map((detail, index) => ({ source: "Message", impact: index === 0 && local.score >= 50 ? "High" : "Medium", detail })),
      ...links.flatMap((link) => link.reasons.map((detail) => ({ source: link.domain, impact: link.riskScore >= 67 ? "High" : link.riskScore >= 34 ? "Medium" : "Low", detail }))),
    ].slice(0, 18),
    links,
    providers,
    iocs: extractIocs(message, urls),
    analysis: {
      inputType: urls.length === 0 ? "Message" : messageWithoutUrls.length < 8 ? "URL" : "Message + URL",
      rulesEvaluated:
        categoryRules.reduce((sum, rule) => sum + rule.patterns.length, 0) +
        urgencyPatterns.length +
        credentialPatterns.length +
        credentialRequestPatterns.length +
        paymentPatterns.length +
        consequencePatterns.length +
        rewardPatterns.length +
        callToActionPatterns.length +
        impersonationPatterns.length +
        secrecyPatterns.length +
        authorityPatterns.length +
        evasionPatterns.length +
        benignContextPatterns.length +
        routineAccountNoticePatterns.length,
      messageStats: local.stats,
      detectedLanguage: local.detectedLanguage,
      signals: local.signals,
      categoryMatches: local.categories,
      context: local.context,
      providerCoverage,
      timing: {
        localAnalysisMs,
        liveChecksMs,
        totalMs: Math.round(performance.now() - scanStartedAt),
      },
    },
    deepScan: {
      checkedExistingReport: mode === "deep" && urls.length > 0,
      canSubmitFreshAnalysis: mode === "deep" && urls.length > 0 && Boolean(env.VIRUSTOTAL_API_KEY),
      urls,
      privacyNotice:
        "Submitting starts a new VirusTotal analysis. The URL and resulting report may be shared with VirusTotal and its security community. Do not submit private, one-time, internal, or credential-bearing links.",
      timingNotice:
        "A fresh VirusTotal scan runs on VirusTotal infrastructure. Queue and engine response time can vary; ScamShield will keep its own result visible while tracking the external analysis.",
    },
    limits: { maxUrls: MAX_URLS, truncatedUrls: (message.match(/https?:\/\//gi)?.length ?? 0) > MAX_URLS },
  };
}

async function handleScan(request: Request, env: ScannerEnv, ctx?: ScannerContext) {
  const parsedBody = await parseJsonObject(request, MAX_SCAN_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const body = parsedBody.body ?? {};

  const message = cleanMessage(body.message);
  const mode = body.mode === "deep" ? "deep" : "quick";
  if (!message) return jsonResponse({ error: "Paste a message or link before starting a scan." }, 400);
  if (message.length > MAX_MESSAGE_LENGTH) {
    return jsonResponse({ error: `Input is too long. The maximum is ${MAX_MESSAGE_LENGTH.toLocaleString()} characters.` }, 413);
  }

  const limit = mode === "deep" ? 5 : 20;
  let rate;
  try {
    rate = await checkRateLimit(request, env, mode, limit, 60);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: mode,
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: `Too many ${mode} scans. Try again in ${rate.retryAfter} seconds.` },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (verification.misconfigured) {
    return jsonResponse({ error: "Human verification is temporarily unavailable." }, 503);
  }
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  const result = await runScan(message, mode, env, ctx);
  return jsonResponse(result, 200, rateLimitHeaders(rate));
}

async function handleDeepSubmit(request: Request, env: ScannerEnv) {
  const parsedBody = await parseJsonObject(request, MAX_DEEP_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const body = parsedBody.body ?? {};
  if (body.consent !== true) return jsonResponse({ error: "Explicit consent is required before sending a URL to VirusTotal." }, 400);
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "Fresh VirusTotal analysis is not configured on this deployment." }, 503);

  const urlValue = typeof body.url === "string" ? body.url.trim() : "";
  const urlBlock = externalUrlBlockReason(urlValue, true);
  if (urlBlock) return jsonResponse({ error: urlBlock }, 400);
  const parsed = new URL(normalizedProviderUrl(urlValue));

  let rate;
  try {
    rate = await checkRateLimit(request, env, "deep-submit", 2, 600);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: "deep-submit",
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: `Fresh analysis limit reached. Try again in ${rate.retryAfter} seconds.` },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (verification.misconfigured) {
    return jsonResponse({ error: "Human verification is temporarily unavailable." }, 503);
  }
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  try {
    const form = new URLSearchParams({ url: parsed.href });
    const response = await fetchWithTimeout(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": env.VIRUSTOTAL_API_KEY,
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: form.toString(),
      },
      8_000,
    );
    const data = await readProviderJson(response) as { data?: { id?: string } } | null;
    if (!response.ok || !data?.data?.id) {
      return jsonResponse({ error: response.status === 429 ? "VirusTotal rate limit reached. Try again later." : "VirusTotal did not accept the analysis request." }, response.status === 429 ? 429 : 502);
    }
    const statusToken = await createStatusToken(data.data.id, env);
    if (!statusToken) return jsonResponse({ error: "Secure analysis tracking could not be initialized." }, 500);
    return jsonResponse({
      analysisId: data.data.id,
      statusToken,
      status: "queued",
      url: parsed.href,
      message: "VirusTotal accepted the URL. ScamShield will now track the analysis until it finishes.",
      pollAfterMs: 750,
    });
  } catch {
    return jsonResponse({ error: "VirusTotal could not be reached or the request timed out." }, 502);
  }
}

async function handleDeepStatus(request: Request, env: ScannerEnv) {
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "VirusTotal is not configured." }, 503);
  const requestUrl = new URL(request.url);
  const analysisId = requestUrl.searchParams.get("id")?.trim() ?? "";
  if (!/^[-\w]+$/.test(analysisId) || analysisId.length > 200) return jsonResponse({ error: "Invalid analysis ID." }, 400);
  const statusToken = request.headers.get("x-scamshield-status-token")?.trim() ?? "";
  if (!await verifyStatusToken(analysisId, statusToken, env)) {
    return jsonResponse({ error: "This analysis tracking token is invalid or expired." }, 403);
  }

  let rate;
  try {
    rate = await checkRateLimit(request, env, "deep-status", 30, 60);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: "deep-status",
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: "Polling too quickly. Wait a moment and try again." },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  try {
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, accept: "application/json" },
    });
    const data = await readProviderJson(response) as {
      data?: { attributes?: { status?: string; stats?: Record<string, number>; date?: number } };
    } | null;
    if (!response.ok) return jsonResponse({ error: response.status === 429 ? "VirusTotal rate limit reached. Try again later." : "Analysis status is temporarily unavailable." }, response.status === 429 ? 429 : 502);
    const attributes = data?.data?.attributes ?? {};
    const status = attributes.status ?? "queued";
    const stats = attributes.stats ?? null;
    const verdict = vtVerdict(stats);
    const engineCount = stats ? Object.values(stats).reduce((sum, count) => sum + count, 0) : 0;
    return jsonResponse({
      status,
      completed: status === "completed",
      stats,
      verdict: status === "completed" ? verdict.label : null,
      riskState: status === "completed" ? verdict.state : "pending",
      analyzedAt: attributes.date ?? null,
      engineCount,
      pollAfterMs: status === "completed" ? 0 : status === "queued" ? 1_500 : 1_000,
    });
  } catch {
    return jsonResponse({ error: "Analysis status could not be retrieved." }, 502);
  }
}

export async function handleScannerApi(request: Request, env: ScannerEnv, ctx?: ScannerContext): Promise<Response | null> {
  const url = new URL(request.url);

  if (url.pathname === "/health" && request.method === "GET") {
    return jsonResponse({ status: "ok" });
  }
  if (url.pathname === "/api/config" && request.method === "GET") {
    return jsonResponse({
      turnstileSiteKey: env.TURNSTILE_SITE_KEY ?? null,
      turnstileConfigured: Boolean(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY),
    });
  }
  const methods: Record<string, "GET" | "POST"> = {
    "/health": "GET",
    "/api/config": "GET",
    "/api/scan": "POST",
    "/api/deep/submit": "POST",
    "/api/deep/status": "GET",
  };
  const allowedMethod = methods[url.pathname];
  if (allowedMethod && request.method !== allowedMethod) {
    return jsonResponse({ error: "Method not allowed." }, 405, { allow: allowedMethod });
  }
  if ((url.pathname === "/api/scan" || url.pathname === "/api/deep/submit") && !isTrustedWriteRequest(request)) {
    return jsonResponse({ error: "Cross-site requests are not allowed." }, 403);
  }
  if (url.pathname === "/api/scan") return handleScan(request, env, ctx);
  if (url.pathname === "/api/deep/submit") return handleDeepSubmit(request, env);
  if (url.pathname === "/api/deep/status") return handleDeepStatus(request, env);
  if (url.pathname.startsWith("/api/") || url.pathname === "/health") {
    return jsonResponse({ error: "Not found." }, 404);
  }
  return null;
}
