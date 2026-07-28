export interface LocalizedTrainingSample {
  id: string;
  text: string;
  label: 0 | 1;
  source: "authority-derived-de-bhs-scam" | "synthetic-de-bhs-hard-negative";
}

const links = [
  "https://konto-pruefung.example",
  "https://sicher-aktualisieren.example",
  "https://status-paket.example",
  "https://kundenportal-check.example",
];

const germanScamTemplates = [
  (brand: string, link: string) =>
    `${brand}: Ihre Banking-App-Registrierung läuft in Kürze ab. Hier erneuern: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Ihr Konto wurde vorübergehend eingeschränkt. Bestätigen Sie Ihre Angaben über den Link: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Ihr Paket wird im Sortierzentrum aufbewahrt. Prüfen Sie die Sendungsverfolgung und zahlen Sie die Zollgebühr: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Die Zustellung ist fehlgeschlagen. Aktualisieren Sie Ihre Adresse, damit das Paket nicht zurückgeschickt wird: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Sie haben einen unbezahlten Strafzettel. Bezahlen Sie den Betrag umgehend hier: ${link}`,
];

const bhsScamTemplates = [
  (brand: string, link: string) =>
    `${brand}: Vaš račun je privremeno ograničen. Potvrdite lične podatke putem veze: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Kartica je blokirana zbog sumnjive aktivnosti. Ažurirajte podatke odmah: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Pošiljka nije isporučena zbog neplaćenih carinskih dažbina. Platite naknadu: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Dostava nije uspjela zbog nepotpune adrese. Potvrdite adresu na poveznici: ${link}`,
  (brand: string, link: string) =>
    `${brand}: Evidentirana je neplaćena kazna. Izmirite dug odmah putem linka: ${link}`,
];

const germanBrands = ["Sparkasse", "Volksbank", "Deutsche Post", "DHL"];
const bhsBrands = ["ASA Banka", "Raiffeisen banka", "BH Pošta", "Pošta Srpske"];

function expandScams(
  prefix: string,
  brands: string[],
  templates: Array<(brand: string, link: string) => string>,
) {
  return templates.flatMap((template, templateIndex) =>
    brands.flatMap((brand, brandIndex) =>
      links.map((link, linkIndex) => ({
        id: `${prefix}-scam-${templateIndex}-${brandIndex}-${linkIndex}`,
        text: template(brand, link),
        label: 1 as const,
        source: "authority-derived-de-bhs-scam" as const,
      }))
    )
  );
}

const germanHardNegatives = [
  "Sparkasse: Ihre Kartenzahlung über 24,90 EUR wurde erfolgreich ausgeführt. Sie müssen nichts unternehmen.",
  "Ihre pushTAN wurde aktiviert. Geben Sie TAN und Sicherheitscodes niemals an andere Personen weiter.",
  "Das Paket wurde heute erfolgreich an Ihrer Adresse zugestellt.",
  "Ihre Sendung liegt in der vereinbarten Filiale zur Abholung bereit. Bringen Sie einen Ausweis mit.",
  "Der Termin bei Ihrer Bank ist am Dienstag um 10 Uhr. Eine Antwort ist nicht erforderlich.",
  "Die Zollabfertigung Ihrer Bestellung ist abgeschlossen. Es fallen keine weiteren Gebühren an.",
  "Meine neue Nummer ist bereits im Familienchat gespeichert.",
  "Die Rechnung wurde bezahlt und der Betrag ist auf Ihrem Kundenkonto verbucht.",
  "Die Bank fragt niemals per Nachricht nach Passwort, PIN oder TAN.",
  "Ihre Adresse wurde wie von Ihnen beauftragt aktualisiert.",
];

const bhsHardNegatives = [
  "Banka: Vaša kartična transakcija od 24,90 KM je uspješno izvršena. Nije potrebna nikakva radnja.",
  "Vaš jednokratni sigurnosni kod je 481920. Nikome ga ne dijelite.",
  "Paket je danas uspješno dostavljen na vašu adresu.",
  "Pošiljka je spremna za preuzimanje u poslovnici. Ponesite lični dokument.",
  "Termin u banci je u utorak u 10 sati. Nije potrebno odgovoriti na poruku.",
  "Carinski postupak za vašu narudžbu je završen. Nema dodatnih troškova.",
  "Moj novi broj je već spremljen u porodičnoj grupi.",
  "Račun je plaćen i uplata je uredno evidentirana.",
  "Banka nikada ne traži lozinku, PIN ili sigurnosni kod putem poruke.",
  "Adresa je ažurirana prema vašem ranijem zahtjevu.",
];

function expandHardNegatives(prefix: string, messages: string[]) {
  const harmlessAdditions = [
    "",
    " Hvala.",
    " Ovo je automatska obavijest.",
    " Za pitanja koristite službeni broj sa kartice.",
  ];
  return messages.flatMap((text, messageIndex) =>
    harmlessAdditions.map((addition, additionIndex) => ({
      id: `${prefix}-legitimate-${messageIndex}-${additionIndex}`,
      text: `${text}${addition}`,
      label: 0 as const,
      source: "synthetic-de-bhs-hard-negative" as const,
    }))
  );
}

export const localizedTrainingExamples: LocalizedTrainingSample[] = [
  ...expandScams("de", germanBrands, germanScamTemplates),
  ...expandScams("bhs", bhsBrands, bhsScamTemplates),
  ...expandHardNegatives("de", germanHardNegatives),
  ...expandHardNegatives("bhs", bhsHardNegatives),
];
