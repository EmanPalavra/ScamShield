import type { EvaluationSample } from "./dataset-types.ts";

type AuthorityExample = Omit<EvaluationSample, "id" | "label" | "source" | "annotationStatus">;

const germanDeliverySource =
  "https://www.verbraucherzentrale.de/wissen/digitale-welt/mobilfunk-und-festnetz/paketdienstsms-vorsicht-abzocke-58988";
const germanMessengerSource =
  "https://www.polizei-beratung.de/themen-und-tipps/betrug/messenger/";
const frenchDeliverySource =
  "https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/escroqueries-livraison-colis";
const frenchBankSource =
  "https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/lhameconnage-au-faux-numero-dopposition-bancaire";
const dutchSources = {
  customs: "https://www.fraudehelpdesk.nl/valse-email/uw-pakket-wordt-bij-de-douane-vastgehouden/",
  parcel: "https://www.fraudehelpdesk.nl/valse-email/uw-pakket-ligt-voor-u-klaar/",
  delayed: "https://www.fraudehelpdesk.nl/valse-email/uw-pakket-heeft-vertraging-opgelopen/",
  digid: "https://www.fraudehelpdesk.nl/valse-email/digid-update/",
  amount: "https://www.fraudehelpdesk.nl/valse-email/openstaand-bedrag-voor-uw-pakket/",
  takeover: "https://www.fraudehelpdesk.nl/valse-email/overname-digid/",
  dhl: "https://www.fraudehelpdesk.nl/valse-email/internationale-dhl-vrachtdiensten-uw-pakketnummer-nl-is-aangekomen-in-ons-magazijn-bevestig-alstublieft-uw-afleveradres/",
  fedex: "https://www.fraudehelpdesk.nl/valse-email/ons-team-kon-uw-pakket-niet-bezorgen/",
  import: "https://www.fraudehelpdesk.nl/valse-email/actie-nodig-betaling-invoerrechten/",
};
const certRsPdf = "https://www.cert.rs/files/shares/Smising%20i%20razvoj%20SMS%20prevara%20lat.pdf";
const certRsNetflix =
  "https://www.cert.rs/rs/obavestenje/1324-Aktuelna-kampanja-usmerena-na-korisnike-Netflix-a.html";

const examples: AuthorityExample[] = [
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "[DHL] Benachrichtigung über fehlgeschlagene Zustellung. Ihr Paket wurde aufgrund einer unklaren Lieferadresse nicht zugestellt. Bitte aktualisieren Sie Ihre Adresse: https://example.invalid/dhl",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Ihr Paket wurde im Verteilerzentrum angehalten. Verfolgen Sie Ihre Sendung hier: https://example.invalid/sendung",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Hallo, Ihr Paket steht noch aus. Bestätigen Sie Ihre Angaben hier: https://example.invalid/post Deutsche Post",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Ihr Paket hat Verspätung. Jetzt Lieferung bestätigen: https://example.invalid/lieferung",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Wir haben ein PAKET vom August für Sie gefunden. Bestätigen Sie hier die Lieferung: https://example.invalid/paket",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Lieferproblem. Folgen Sie dem Link, um einen neuen Liefertermin zu vereinbaren: https://example.invalid/termin",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Hinweis: Ihr Paket wird an den Absender zurückgeschickt: https://example.invalid/status",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Delivery / postal scam",
    text: "Ihr Paket wurde bei der Abholstelle abgegeben. Sie können Ihr Paket hier abholen: https://example.invalid/abholung",
    sourceUrl: germanDeliverySource,
  },
  {
    language: "German",
    scamType: "Romance / impersonation scam",
    text: "Hallo Mama, das ist meine neue Handynummer. Speichere sie bitte und schreib mir auf WhatsApp.",
    sourceUrl: germanMessengerSource,
  },
  {
    language: "German",
    scamType: "Romance / impersonation scam",
    text: "Hallo Papa, mein Handy ist kaputt. Das ist meine neue Nummer. Kannst du dringend eine Rechnung für mich überweisen?",
    sourceUrl: germanMessengerSource,
  },
  {
    language: "French",
    scamType: "Delivery / postal scam",
    text: "Bonjour, c'est le livreur. Votre colis ne rentrait pas dans la boîte aux lettres. Veuillez choisir un autre créneau ou point relais sur https://example.invalid/colis",
    sourceUrl: frenchDeliverySource,
  },
  {
    language: "French",
    scamType: "Delivery / postal scam",
    text: "Votre colis a été organisé pour la livraison, veuillez vérifier vos informations ici : https://example.invalid/livraison",
    sourceUrl: frenchDeliverySource,
  },
  {
    language: "French",
    scamType: "Delivery / postal scam",
    text: "Votre colis a été envoyé. Veuillez le vérifier et le recevoir à temps : https://example.invalid/suivi",
    sourceUrl: frenchDeliverySource,
  },
  {
    language: "French",
    scamType: "Delivery / postal scam",
    text: "Votre commande a été expédiée, veuillez cliquer pour vérifier : https://example.invalid/commande",
    sourceUrl: frenchDeliverySource,
  },
  {
    language: "French",
    scamType: "Account takeover / phishing",
    text: "Pour la sécurité de votre compte Apple Store, votre compte est contraint et nécessite une nouvelle authentification : https://example.invalid/apple",
    sourceUrl: frenchDeliverySource,
  },
  {
    language: "French",
    scamType: "Brand impersonation / fake charge",
    text: "Merci pour votre commande n°8945623 – 589,99 € seront débités. Un problème ? Appelez immédiatement le 09 XX XX XX XX. SOS carte",
    sourceUrl: frenchBankSource,
  },
  {
    language: "French",
    scamType: "Brand impersonation / fake charge",
    text: "Votre achat de 594,98 EUR chez Darty a bien été enregistré. Si vous n'avez pas initié ce paiement, contactez vite le service opposition au 07 XX XX XX XX.",
    sourceUrl: frenchBankSource,
  },
  {
    language: "French",
    scamType: "Brand impersonation / fake charge",
    text: "Crédit Agricole : un paiement de 657,99 € est en cours de validation. Si vous n'en êtes pas l'auteur, veuillez contacter le service de sécurité au 09 XX XX XX XX.",
    sourceUrl: frenchBankSource,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Er ontbreekt nog een kleine stap om uw pakket te kunnen bezorgen. Rond de controle binnen 48 uur af. Bekijk uw zending: https://example.invalid/zending",
    sourceUrl: dutchSources.customs,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Er is een poging gedaan om uw pakket af te leveren, maar dit is niet gelukt vanwege ontbrekende gegevens. Klik hier om uw levering opnieuw te plannen: https://example.invalid/levering",
    sourceUrl: dutchSources.parcel,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Uw pakket heeft vertraging opgelopen. Kies een nieuw bezorgmoment. Als u binnen 5 dagen geen actie onderneemt, wordt het pakket teruggestuurd: https://example.invalid/bezorging",
    sourceUrl: dutchSources.delayed,
  },
  {
    language: "Dutch",
    scamType: "Account takeover / phishing",
    text: "DigiD update. Status: controle vereist. Controleer en bevestig uw gegevens via het officiële portaal: https://example.invalid/digid",
    sourceUrl: dutchSources.digid,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Actie vereist. Openstaand bedrag voor uw pakket: € 13,50. Stel nu uw automatische incasso in zodat uw pakket definitief vrijgegeven wordt: https://example.invalid/betalen",
    sourceUrl: dutchSources.amount,
  },
  {
    language: "Dutch",
    scamType: "Account takeover / phishing",
    text: "Belangrijke update: Overname DigiD. Wij verzoeken u om uw naam, adresgegevens, bankrekeningnummer en contactgegevens te actualiseren: https://example.invalid/bijwerken",
    sourceUrl: dutchSources.takeover,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "DHL: uw pakket is aangekomen. Vanwege ontbrekende informatie kunnen wij niet bezorgen. Los dit binnen vijf werkdagen op, anders sturen wij het pakket terug: https://example.invalid/dhl",
    sourceUrl: dutchSources.dhl,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Levering van FedEx-pakket mislukt. Wij konden het pakket niet afleveren. Controleer de status van uw pakket: https://example.invalid/fedex",
    sourceUrl: dutchSources.fedex,
  },
  {
    language: "Dutch",
    scamType: "Delivery / postal scam",
    text: "Uw pakket wordt niet vrijgegeven voor levering totdat de openstaande douanekosten zijn betaald. Voer de betaling zo spoedig mogelijk uit: https://example.invalid/invoerrechten",
    sourceUrl: dutchSources.import,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Prize / advance-fee scam",
    text: "Osvojili ste nagradu, javite se odmah na ovaj broj da biste je preuzeli.",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Romance / impersonation scam",
    text: "Ćao, pišem ti sa novog broja. Molim te uplati mi dopunu pripejd kredita za ovaj broj.",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Romance / impersonation scam",
    text: "Mama, pozovi me na ovaj broj, izgubio sam telefon.",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Brand impersonation / fake charge",
    text: "Zabeležen je Vaš saobraćajni prekršaj. Kliknite na link da biste platili kaznu: https://example.invalid/kazna",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Delivery / postal scam",
    text: "Vaš paket je zadržan. Platite 150 din za carinjenje da biste dobili paket: https://example.invalid/paket",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Account takeover / phishing",
    text: "Banka: vaš nalog je privremeno blokiran. Prijavite se ovde da biste mogli da nastavite da koristite usluge banke: https://example.invalid/banka",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Account takeover / phishing",
    text: "Netflix pretplata nije produžena. Potvrdite karticu ovde: https://example.invalid/netflix",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Delivery / postal scam",
    text: "Ваш пакет број 77344433 подлеже царинама. Молимо вас да посетите https://example.invalid/posta да пратите процедуру и добијете га.",
    sourceUrl: certRsPdf,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Account takeover / phishing",
    text: "NETFLIX: Vaša poslednja uplata je odbijena. Proverite svoje podatke na: https://example.invalid/netflix-login",
    sourceUrl: certRsNetflix,
  },
  {
    language: "Bosnian / Croatian / Serbian",
    scamType: "Brand impersonation / fake charge",
    text: "Саобраћајна казна од 114.16 динара није плаћена. Платите одмах: https://example.invalid/putevi",
    sourceUrl: certRsPdf,
  },
];

export const authorityScamExamples: EvaluationSample[] = examples.map((example, index) => ({
  ...example,
  id: `authority-scam-${String(index + 1).padStart(3, "0")}`,
  label: "scam",
  source: `authority-scam-${example.language.toLowerCase().replace(/[^a-z]+/g, "-").replace(/^-|-$/g, "")}`,
  annotationStatus: "authority-confirmed",
  evaluationSplit: "calibration",
  evidenceKind: "authority-described",
}));
