import type { EvaluationSample, EvaluationSplit, EvidenceKind } from "./dataset-types.ts";

export type BhsCountry = "BA" | "HR" | "RS";
export type BhsChannel = "sms" | "imessage" | "rcs" | "whatsapp" | "viber" | "web-message";

interface BhsRealWorldRecord {
  id: string;
  country: BhsCountry;
  locale: "bs-BA" | "hr-HR" | "sr-Latn-RS" | "sr-Cyrl-RS";
  channel: BhsChannel;
  publishedAt: string;
  scamType: string;
  text: string;
  sourceAuthority: string;
  sourceUrl: string;
  evidenceKind: EvidenceKind;
  evaluationSplit: EvaluationSplit;
}

const BA_POST_MARCH = "https://www.posta.ba/upozorenje-na-lazne-sms-poruke-ne-nasjedajte-na-pokusaje-prevare/";
const BA_POST_JUNE = "https://www.posta.ba/upozorenje-korisnicima-ne-klikajte-na-sumnjive-linkove-iz-sms-poruka/";
const BA_POST_NOVEMBER = "https://www.posta.ba/nove-prevare-putem-laznih-poruka-ne-otvarajte-link-bh-posta-dostava/";
const BA_POST_DECEMBER = "https://www.posta.ba/ne-otvarajte-sumnjive-linkove-nova-pojava-laznih-sms-poruka-o-dostavi-posiljki/";
const BA_POST_JULY_2026 = "https://www.posta.ba/ne-otvarajte-lazne-poruke-o-neuspjeloj-isporuci-posiljki-ili-neplacenim-carinskim-dazbinama/";
const BA_RAIFFEISEN = "https://app.raiffeisenbank.ba/en/node/4156";
const BA_UNICREDIT = "https://www.unicredit.ba/ba/stanovnistvo/proizvodi_i_usluge/bankarstvo_u_pokretu/Obavijest_za_klijente.html";
const BA_BHT_POINTS = "https://www.bhtelecom.ba/usluge-za-privatne-korisnike/2026/03/upozorenje-za-korisnike-usluga-2/";
const BA_MTEL_PRIZE = "https://mtel.ba/Korisnicka-zona/Vijesti/a37670-Vazno-obavjestenje-za-korisnike-o-neovlastenim-porukama-o-novcanim-nagradama.html";

const HR_CHILD = "https://policija.gov.hr/vijesti/dobili-ste-sms-poruku-svog-djeteta-da-ima-novi-broj-mobitela/8896?big=0";
const HR_WHATSAPP = "https://www.cert.hr/upozorenje-oprezno-s-whatsapp-porukama/";
const HR_FACEBOOK_VOTE = "https://www.cert.hr/upozorenje-prijevara-putem-facebooka-s-ciljem-krade-whatsapp-racuna/";
const HR_NETFLIX = "https://www.cert.hr/upozorenje-lazne-sms-poruke-u-kojima-se-napadaci-predstavljaju-kao-netflix/";
const HR_HZZO = "https://www.cert.hr/upozorenje-lazne-hzzo-stranice/";
const HR_HEP = "https://www.cert.hr/upozorenje-napadaci-se-i-dalje-predstavljaju-kao-hep-te-prijete-iskljucivanjem-struje/";
const HR_FINE = "https://www.cert.hr/upozorenje-u-tijeku-je-sms-prijevara-s-placanjem-kazni/";

const RS_BOOKLET = "https://www.cert.rs/files/shares/Smising%20i%20razvoj%20SMS%20prevara%20lat.pdf";
const RS_FINE_2025 = "https://www.cert.rs/obavestenje/1421-Fi%C5%A1ing-kampanja-koja-zloupotrebljava-ime-%E2%80%9EPutevi-Srbije%E2%80%9C.html";
const RS_FINE_JANUARY = "https://www.cert.rs/rs/obavestenje/1494-Aktuelna-fi%C5%A1ing-kampanja-koja-zloupotrebljava-ime-JP-%E2%80%9EPutevi-Srbije%E2%80%9C.html";
const RS_FINE_MARCH = "https://www.cert.rs/rs/obavestenje/1519-Ponovo-aktuelna-fi%C5%A1ing-kampanja-koja-zloupotrebljava-ime-JP-%E2%80%9EPutevi-Srbije%E2%80%9C.html";
const RS_WHATSAPP = "https://www.cert.rs/rs/obavestenje/1513-Aktuelna-fi%C5%A1ing-kampanja-usmerena-na-korisnike-aplikacije-WhatsApp.html";
const RS_NBS_POINTS = "https://www.nbs.rs/sr/scripts/showcontent/index.html?id=20711";

// Verbatim rows are transcribed from an authority-published screenshot or quote.
// Live malicious URLs, phone numbers, and personal identifiers are removed or defanged.
// Authority-described rows retain only details explicitly stated by the cited authority.
export const bhsCurrentRealWorldRecords: BhsRealWorldRecord[] = [
  {
    id: "bhs-real-ba-posta-2025-03",
    country: "BA",
    locale: "bs-BA",
    channel: "imessage",
    publishedAt: "2025-03-20",
    scamType: "Delivery / postal scam",
    text: "Pošta Bosne i Hercegovine: Vaš paket je stigao u skladište, ali ne može biti isporučen zbog nepotpunih podataka o adresi. Molimo provjerite adresu na linku. https://example.invalid/posta (Odgovorite \"Da\" i izađite i ponovo pošaljite tekstualnu poruku da aktivirate vezu, ili kopirajte vezu i otvorite je u Safariju.) Poslat ćemo vam je u roku od 24 sata i nadamo se da ste zadovoljni.",
    sourceAuthority: "BH Pošta",
    sourceUrl: BA_POST_MARCH,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-posta-2025-06",
    country: "BA",
    locale: "bs-BA",
    channel: "imessage",
    publishedAt: "2025-06-17",
    scamType: "Delivery / postal scam",
    text: "Vaš paket je stigao u naše lokalno skladište, ali zbog netačne ili nepotpune adrese za isporuku, nismo u mogućnosti izvršiti dostavu. Molimo vas da putem sljedeće veze potvrdite da je vaša adresa tačna; u suprotnom, paket će biti vraćen pošiljaocu u roku od 24 sata. https://example.invalid/dostava (Odgovorite sa \"Y\" i ponovo otvorite aktivacioni link iz poruke, ili kopirajte link i zalijepite ga u vaš pretraživač.) Ako imate bilo kakva pitanja ili vam je potrebna pomoć, slobodno nas kontaktirajte. BH POŠTA",
    sourceAuthority: "BH Pošta",
    sourceUrl: BA_POST_JUNE,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-posta-marketplace-2025-11",
    country: "BA",
    locale: "bs-BA",
    channel: "web-message",
    publishedAt: "2025-11-11",
    scamType: "Marketplace / payment scam",
    text: "Platila sam za robu i dostavu putem sajta za dostavu i preuzmite novac. Kurirska služba će vas kontaktirati nakon što primi sredstva. https://example.invalid/preuzmi",
    sourceAuthority: "BH Pošta",
    sourceUrl: BA_POST_NOVEMBER,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-posta-2025-12",
    country: "BA",
    locale: "bs-BA",
    channel: "imessage",
    publishedAt: "2025-12-11",
    scamType: "Delivery / postal scam",
    text: "【BH POŠTA】Budući da je naš sistem otkrio nepotpune podatke o adresi, nismo u mogućnosti da izvršimo dostavu. Paket je dostavljen u naše skladište 10. decembar 2025. Molimo vas da što prije potvrdite ili ažurirate svoju adresu koristeći link ispod kako biste ubrzali dostavu. Ako ne ažurirate adresu na vrijeme, paket će biti vraćen pošiljaocu. https://example.invalid/adresa Odgovorite sa \"Da\" i kliknite na link ili ga kopirajte i zalijepite u svoj pretraživač da biste ga aktivirali.",
    sourceAuthority: "BH Pošta",
    sourceUrl: BA_POST_DECEMBER,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-ba-raiffeisen-locked",
    country: "BA",
    locale: "bs-BA",
    channel: "sms",
    publishedAt: "2020-04-01",
    scamType: "Account takeover / phishing",
    text: "Raiffeisen banka, sumnjiv pokušaj prijave, vaš račun je zaključan iz sigurnosnih razloga, pokušajte ovjeriti svih račun dolje navedenom vezom",
    sourceAuthority: "Raiffeisen Bank BiH",
    sourceUrl: BA_RAIFFEISEN,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-ba-posta-customs-2026-07",
    country: "BA",
    locale: "bs-BA",
    channel: "web-message",
    publishedAt: "2026-07-07",
    scamType: "Delivery / postal scam",
    text: "Ažuriranje pošiljke. Poštovani korisniče, obavještavamo vas da je vaša pošiljka trenutno zadržana zbog troškova dostave ili neplaćenih carinskih dažbina. Kako biste omogućili nastavak isporuke, molimo vas da izvršite potrebnu uplatu što je prije moguće. Tip pošiljke: Paket. Status: Na čekanju. Izvrši uplatu. Nakon potvrde uplate, vaša pošiljka će biti obrađena i spremna za dostavu. Ukoliko ne poduzmete nikakvu radnju, pošiljka će ostati na čekanju.",
    sourceAuthority: "BH Pošta",
    sourceUrl: BA_POST_JULY_2026,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-unicredit-mba-locked",
    country: "BA",
    locale: "hr-HR",
    channel: "sms",
    publishedAt: "2025-01-01",
    scamType: "Account takeover / phishing",
    text: "Vaša usluga mobilnog bankarstva m-ba je zaključana. Deblokirajte je putem poveznice i unesite podatke kartice i aktivacijski kod.",
    sourceAuthority: "UniCredit Bank BiH",
    sourceUrl: BA_UNICREDIT,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-bhtelecom-points-2026-03",
    country: "BA",
    locale: "bs-BA",
    channel: "rcs",
    publishedAt: "2026-03-10",
    scamType: "Prize / rewards scam",
    text: "BH Telecom – Obavještenje o bodovima: iskoristite bodove iz programa lojalnosti putem priloženog linka.",
    sourceAuthority: "BH Telecom",
    sourceUrl: BA_BHT_POINTS,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-ba-mtel-prize-2026-05",
    country: "BA",
    locale: "sr-Latn-RS",
    channel: "viber",
    publishedAt: "2026-05-15",
    scamType: "Prize / rewards scam",
    text: "Čestitamo, osvojili ste novčanu nagradu kompanije m:tel. Za preuzimanje nagrade pošaljite lične podatke i fotografije ličnih dokumenata.",
    sourceAuthority: "m:tel BiH",
    sourceUrl: BA_MTEL_PRIZE,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-child-new-number-2025",
    country: "HR",
    locale: "hr-HR",
    channel: "sms",
    publishedAt: "2025-06-06",
    scamType: "Family impersonation / emergency scam",
    text: "Mama ovo je moj novi broj telefona, možeš li mi poslati poruku na whatsappu https://example.invalid/whatsapp",
    sourceAuthority: "Ravnateljstvo policije RH",
    sourceUrl: HR_CHILD,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-whatsapp-vote-2025-a",
    country: "HR",
    locale: "hr-HR",
    channel: "whatsapp",
    publishedAt: "2025-05-06",
    scamType: "Account takeover / phishing",
    text: "Dobro jutro! Molim vas glasajte za Anu u ovom natječaju, ona je kći moje prijateljice, glavna nagrada je besplatna stipendija za sljedeću godinu, to joj puno znači. Hvala! https://example.invalid/glasanje",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_WHATSAPP,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-whatsapp-vote-2025-b",
    country: "HR",
    locale: "hr-HR",
    channel: "whatsapp",
    publishedAt: "2025-05-06",
    scamType: "Account takeover / phishing",
    text: "Pozdrav, molim te glasaj za Anu u ovoj anketi, ona je kći moje bliske prijateljice. Pobjeda donosi besplatnu stipendiju za sljedeću akademsku godinu, što joj je od velike važnosti. Hvala ti! https://example.invalid/anketa",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_WHATSAPP,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-whatsapp-loan-2025",
    country: "HR",
    locale: "hr-HR",
    channel: "whatsapp",
    publishedAt: "2025-05-06",
    scamType: "Family impersonation / emergency scam",
    text: "Bok, možete li mi posuditi 800 eur na moj račun? Vratit ću ih sutra. Hvala!",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_WHATSAPP,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-facebook-vote-2026",
    country: "HR",
    locale: "hr-HR",
    channel: "whatsapp",
    publishedAt: "2026-01-05",
    scamType: "Account takeover / phishing",
    text: "Bok! Možete li, molim vas, glasati za Mariju u ovom natjecanju? Ona je kći mog prijatelja. Prva nagrada je besplatna stipendija za sljedeću godinu. To joj puno znači. Hvala vam puno!",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_FACEBOOK_VOTE,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-netflix-2025",
    country: "HR",
    locale: "hr-HR",
    channel: "sms",
    publishedAt: "2025-10-10",
    scamType: "Account takeover / phishing",
    text: "NETFLIX: Vasa zadnja uplata je odbijena. Vas racun ce biti suspendiran 08/10. Molimo azurirajte svoje podatke o placanju odmah: https://example.invalid/netflix",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_NETFLIX,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-hr-hzzo-2025",
    country: "HR",
    locale: "hr-HR",
    channel: "rcs",
    publishedAt: "2025-09-05",
    scamType: "Account takeover / phishing",
    text: "HZZO: Poštovani, vaša zdravstvena iskaznica zahtijeva ažuriranje. Kako biste osigurali očuvanje svojih prava, molimo vas da u najkraćem mogućem roku ispunite potrebne obrasce. https://example.invalid/hzzo",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_HZZO,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-hep-2025",
    country: "HR",
    locale: "hr-HR",
    channel: "sms",
    publishedAt: "2025-04-16",
    scamType: "Utility / unpaid bill scam",
    text: "HEP Plaćanje vaše posljednje fakture nije uspjelo. HEP zadržava pravo isključiti vašu električnu energiju u roku od 24 sata. Molimo vas da regulirate svoju situaciju na: https://example.invalid/hep",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_HEP,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-hr-traffic-fine-2026",
    country: "HR",
    locale: "hr-HR",
    channel: "sms",
    publishedAt: "2026-05-12",
    scamType: "Brand impersonation / fake charge",
    text: "[Ministarstvo unutarnjih poslova RH] Obavijest o prometnoj kazni. Vaš prometni prekršaj je zabilježen i unesen u sustav. Broj predmeta: 2026-PRE-44781. Sustav je potvrdio da je vaša prometna kazna ušla u završnu fazu naplate. Kaznu morate platiti putem službene web stranice prije 23:59 13. svibnja. Iskoristite popust od 50% – ako kaznu platite u roku od 24 sata, trebate platiti samo polovicu iznosa! Ako ne platite kaznu na vrijeme, pokrenut ćemo obvezni postupak naplate i naplatiti zakašnjele naknade. https://example.invalid/kazna",
    sourceAuthority: "Nacionalni CERT Hrvatske",
    sourceUrl: HR_FINE,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-rs-fine-short-2025",
    country: "RS",
    locale: "sr-Cyrl-RS",
    channel: "sms",
    publishedAt: "2025-08-04",
    scamType: "Brand impersonation / fake charge",
    text: "Саобраћајна казна од 114.16 динара није плаћена. https://example.invalid/kazna",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_FINE_2025,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-rs-fine-january-2026-a",
    country: "RS",
    locale: "sr-Cyrl-RS",
    channel: "imessage",
    publishedAt: "2026-01-09",
    scamType: "Brand impersonation / fake charge",
    text: "Обавештење о неплаћеним новчаним казнама – Упозорење о заштити права крајњих корисника. Имате неплаћене новчане казне за саобраћајне прекршаје. Уколико их не измирите до 10. јануара 2026. године: биће вам обустављена регистрација возила, ваша возачка дозвола биће суспендована на 30 дана, биће вам наплаћена додатна административна такса од 35%. Предузмите одмах мере како бисте спречили поништење вашег регистрационог сертификата. Платите казну одмах: https://example.invalid/kazna.",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_FINE_JANUARY,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-rs-fine-january-2026-b",
    country: "RS",
    locale: "sr-Cyrl-RS",
    channel: "sms",
    publishedAt: "2026-01-09",
    scamType: "Brand impersonation / fake charge",
    text: "Коначно обавештење Министарства саобраћаја Републике Србије: Извршење казнених мера почиње 10. јануара. Уколико не измирите казну до 9. јануара 2025. године, биће примењене следеће мере: ваш прекршај ће бити унет у базу података, регистрација возила ће бити обустављена, возачка дозвола ће бити обустављена на 30 дана и случај ће бити предат агенцији за наплату са накнадом од 35%. Плати одмах: https://example.invalid/putevi.",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_FINE_JANUARY,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-rs-fine-march-2026",
    country: "RS",
    locale: "sr-Cyrl-RS",
    channel: "imessage",
    publishedAt: "2026-03-02",
    scamType: "Brand impersonation / fake charge",
    text: "„ЈП Путеви Србије“ обавештава Вас: Имате неплаћену саобраћајну казну у нашем систему. Уколико не уплатите до 3. марта 2026. године: регистрација возила биће суспендована, возачка дозвола ће бити привремено повучена, наложиће се административна такса од 35%, могуће су правне и кредитне последице. Уплатите одмах на званичном порталу putevi-srbije: https://example.invalid/putevi. Да активирате линк, одговорите са Y или налепите у прегледач.",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_FINE_MARCH,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "holdout",
  },
  {
    id: "bhs-real-rs-new-number-booklet",
    country: "RS",
    locale: "sr-Latn-RS",
    channel: "sms",
    publishedAt: "2025-12-29",
    scamType: "Family impersonation / emergency scam",
    text: "Ćao pišem ti sa novog broja, molim te uplati mi dopunu pripejd kredita za ovaj broj…",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_BOOKLET,
    evidenceKind: "verbatim-redacted",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-rs-whatsapp-vote-2026",
    country: "RS",
    locale: "sr-Latn-RS",
    channel: "whatsapp",
    publishedAt: "2026-02-12",
    scamType: "Account takeover / phishing",
    text: "Molim te glasaj za mene na ovom takmičenju klikom na link u poruci.",
    sourceAuthority: "Nacionalni CERT Republike Srbije",
    sourceUrl: RS_WHATSAPP,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
  {
    id: "bhs-real-rs-mobile-points-2025",
    country: "RS",
    locale: "sr-Latn-RS",
    channel: "sms",
    publishedAt: "2025-07-09",
    scamType: "Prize / rewards scam",
    text: "Ostvarili ste dovoljan broj poena kod mobilnog operatora. Iskoristite poene i preuzmite nagradu putem linka; za dostavu unesite podatke platne kartice.",
    sourceAuthority: "Narodna banka Srbije",
    sourceUrl: RS_NBS_POINTS,
    evidenceKind: "authority-described",
    evaluationSplit: "calibration",
  },
];

export const bhsCurrentRealWorldSamples: EvaluationSample[] = bhsCurrentRealWorldRecords.map((record) => ({
  id: record.id,
  label: "scam",
  language: "Bosnian / Croatian / Serbian",
  scamType: record.scamType,
  text: record.text,
  source: `bhs-real-${record.country.toLocaleLowerCase()}-${record.sourceAuthority
    .normalize("NFKD")
    .replace(/\p{Diacritic}/gu, "")
    .toLocaleLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")}`,
  sourceUrl: record.sourceUrl,
  annotationStatus: record.evidenceKind === "verbatim-redacted"
    ? "authority-confirmed"
    : "authority-described",
  evidenceKind: record.evidenceKind,
  evaluationSplit: record.evaluationSplit,
}));
