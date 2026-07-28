import type { BhsCountry } from "./bhs-current-real-world.ts";

export interface BhsChallengeSample {
  id: string;
  country: BhsCountry;
  family: string;
  text: string;
  sourceUrl: string;
  provenance: "source-grounded-synthetic";
}

interface ChallengeFamily {
  id: string;
  country: BhsCountry;
  sourceUrl: string;
  texts: string[];
}

const families: ChallengeFamily[] = [
  {
    id: "ba-post-address",
    country: "BA",
    sourceUrl: "https://www.posta.ba/ne-otvarajte-sumnjive-linkove-nova-pojava-laznih-sms-poruka-o-dostavi-posiljki/",
    texts: [
      "BH POŠTA: Dostava nije moguća jer nedostaje broj ulice. Potvrdite adresu danas: https://example.invalid/ba/a1",
      "Vaša pošiljka je vraćena u skladište zbog nepotpunih podataka. Ažurirajte adresu putem https://example.invalid/ba/a2",
      "Paket čeka potvrdu mjesta isporuke. Odgovorite sa DA i otvorite https://example.invalid/ba/a3",
      "Nismo uspjeli uručiti paket. Ispravite podatke za dostavu u roku od 24 sata: https://example.invalid/ba/a4",
      "BH Pošta obavijest: pošiljka će biti vraćena pošiljaocu ako odmah ne potvrdite adresu na https://example.invalid/ba/a5",
    ],
  },
  {
    id: "ba-bank-lock",
    country: "BA",
    sourceUrl: "https://www.unicredit.ba/ba/stanovnistvo/proizvodi_i_usluge/bankarstvo_u_pokretu/Obavijest_za_klijente.html",
    texts: [
      "UniCredit: m-ba je privremeno zaključan. Za nastavak korištenja potvrdite karticu na https://example.invalid/ba/b1",
      "Vaš mobilni pristup banci je blokiran nakon sumnjive prijave. Izvršite verifikaciju: https://example.invalid/ba/b2",
      "Banka: sigurnosna provjera računa nije završena. Ažurirajte podatke odmah putem https://example.invalid/ba/b3",
      "Kartica je ograničena zbog neuobičajene aktivnosti. Potvrdite identitet na https://example.invalid/ba/b4",
      "Posljednje upozorenje banke: račun će ostati zaključan dok ne unesete aktivacijski kod na https://example.invalid/ba/b5",
    ],
  },
  {
    id: "ba-telecom-points",
    country: "BA",
    sourceUrl: "https://www.bhtelecom.ba/usluge-za-privatne-korisnike/2026/03/upozorenje-za-korisnike-usluga-2/",
    texts: [
      "BH Telecom: Vaših 4.850 bodova ističe večeras. Zamijenite ih za telefon na https://example.invalid/ba/c1",
      "Bonus Plus bodovi su spremni za nagradu. Potvrdite dostavu putem https://example.invalid/ba/c2",
      "Obavještenje o bodovima: osvojili ste bežične slušalice. Platite samo dostavu na https://example.invalid/ba/c3",
      "Iskoristite bodove programa lojalnosti prije brisanja računa: https://example.invalid/ba/c4",
      "BH Telecom nagrada čeka potvrdu. Unesite podatke kartice radi dostave: https://example.invalid/ba/c5",
    ],
  },
  {
    id: "ba-marketplace-courier",
    country: "BA",
    sourceUrl: "https://www.posta.ba/nove-prevare-putem-laznih-poruka-ne-otvarajte-link-bh-posta-dostava/",
    texts: [
      "Kupac je već uplatio robu i dostavu. Otvorite BH Pošta obrazac da primite novac: https://example.invalid/ba/d1",
      "Platila sam narudžbu preko kurira. Potvrdite karticu prodavca na https://example.invalid/ba/d2",
      "Novac za vaš oglas je rezervisan. Unesite CVV kako bi kurir izvršio isplatu: https://example.invalid/ba/d3",
      "Dostavna služba čeka potvrdu prodavca. Preuzmite 320 KM putem https://example.invalid/ba/d4",
      "Kupovina je završena. Za prijem uplate unesite broj kartice i jednokratni kod na https://example.invalid/ba/d5",
    ],
  },
  {
    id: "ba-family-number",
    country: "BA",
    sourceUrl: "https://www.cert.rs/files/shares/Smising%20i%20razvoj%20SMS%20prevara%20lat.pdf",
    texts: [
      "Mama, pokvario mi se telefon. Ovo je privremeni broj, javi mi se odmah na WhatsApp.",
      "Tata, izgubila sam mobitel i ne mogu ući u banku. Možeš li mi hitno uplatiti račun?",
      "Babo, pišem sa prijateljevog broja. Treba mi 600 KM danas, vratit ću čim dođem kući.",
      "Ovo je moj novi broj, stari izbriši. Molim te plati mi račun koji uskoro ističe.",
      "Mama, telefon je pao u vodu. Pošalji mi poruku na novi broj, moram te nešto hitno zamoliti.",
    ],
  },
  {
    id: "hr-traffic-fine",
    country: "HR",
    sourceUrl: "https://www.cert.hr/upozorenje-u-tijeku-je-sms-prijevara-s-placanjem-kazni/",
    texts: [
      "MUP RH: Evidentiran je prometni prekršaj. Platite kaznu u 24 sata uz 50% popusta: https://example.invalid/hr/a1",
      "Obavijest o prometnoj kazni: predmet ulazi u postupak ovrhe ako danas ne izvršite uplatu na https://example.invalid/hr/a2",
      "Vaše vozilo zabilježeno je u prekršaju. Pregledajte fotografiju i podmirite nalog: https://example.invalid/hr/a3",
      "Kazna nije plaćena u propisanom roku. Izbjegnite suspenziju vozačke dozvole: https://example.invalid/hr/a4",
      "Službeni portal ePrekršaji: potvrdite podatke vozila i platite umanjeni iznos na https://example.invalid/hr/a5",
    ],
  },
  {
    id: "hr-whatsapp-vote",
    country: "HR",
    sourceUrl: "https://www.cert.hr/upozorenje-prijevara-putem-facebooka-s-ciljem-krade-whatsapp-racuna/",
    texts: [
      "Bok, možeš glasati za Luciju u dječjem natjecanju? Stipendija joj puno znači: https://example.invalid/hr/b1",
      "Molim te podrži Ivanu u anketi. Prijavi se WhatsApp računom i potvrdi glas: https://example.invalid/hr/b2",
      "Moja nećakinja je u finalu natječaja. Nedostaje joj još jedan glas: https://example.invalid/hr/b3",
      "Glasanje završava uskoro, možeš li odabrati Mariju i unijeti kod koji dobiješ: https://example.invalid/hr/b4",
      "Pozdrav! Glasaj za dijete moje prijateljice i potvrdi broj mobitela na https://example.invalid/hr/b5",
    ],
  },
  {
    id: "hr-utility-bill",
    country: "HR",
    sourceUrl: "https://www.cert.hr/upozorenje-napadaci-se-i-dalje-predstavljaju-kao-hep-te-prijete-iskljucivanjem-struje/",
    texts: [
      "HEP: Posljednji račun nije podmiren. Spriječite isključenje električne energije uplatom na https://example.invalid/hr/c1",
      "Plaćanje računa za struju nije uspjelo. Regulirajte dug u roku od 12 sati: https://example.invalid/hr/c2",
      "HEP zadržava pravo obustaviti opskrbu zbog nepodmirene fakture. Platite ovdje: https://example.invalid/hr/c3",
      "Opomena pred isključenje: dugovanje od 47,20 EUR podmirite danas putem https://example.invalid/hr/c4",
      "Vaša uplata je odbijena. Ažurirajte karticu kako biste zadržali opskrbu: https://example.invalid/hr/c5",
    ],
  },
  {
    id: "hr-health-card",
    country: "HR",
    sourceUrl: "https://www.cert.hr/upozorenje-lazne-hzzo-stranice/",
    texts: [
      "HZZO: Zdravstvena iskaznica zahtijeva hitno ažuriranje. Ispunite obrazac na https://example.invalid/hr/d1",
      "Vaša prava iz osiguranja uskoro će biti ograničena. Potvrdite osobne podatke: https://example.invalid/hr/d2",
      "HZZO obavijest: iskaznica nije verificirana. Dovršite postupak putem https://example.invalid/hr/d3",
      "Za nastavak zdravstvenog osiguranja unesite OIB i podatke kartice na https://example.invalid/hr/d4",
      "Rok za obnovu zdravstvene iskaznice istječe danas. Ažurirajte je na https://example.invalid/hr/d5",
    ],
  },
  {
    id: "hr-subscription",
    country: "HR",
    sourceUrl: "https://www.cert.hr/upozorenje-lazne-sms-poruke-u-kojima-se-napadaci-predstavljaju-kao-netflix/",
    texts: [
      "NETFLIX: Zadnja uplata je odbijena. Račun će biti suspendiran, ažurirajte plaćanje: https://example.invalid/hr/e1",
      "Pretplata nije obnovljena zbog greške kartice. Potvrdite podatke danas: https://example.invalid/hr/e2",
      "Vaš Netflix profil čeka naplatu. Spriječite prekid usluge putem https://example.invalid/hr/e3",
      "Posljednja obavijest: članstvo se deaktivira za 6 sati. Prijavite se na https://example.invalid/hr/e4",
      "Nismo mogli obraditi mjesečnu uplatu. Unesite novu karticu na https://example.invalid/hr/e5",
    ],
  },
  {
    id: "rs-road-fine",
    country: "RS",
    sourceUrl: "https://www.cert.rs/rs/obavestenje/1519-Ponovo-aktuelna-fi%C5%A1ing-kampanja-koja-zloupotrebljava-ime-JP-%E2%80%9EPutevi-Srbije%E2%80%9C.html",
    texts: [
      "JP Putevi Srbije: Imate neizmirenu saobraćajnu kaznu. Uplatite do ponoći: https://example.invalid/rs/a1",
      "Коначно обавештење: регистрација возила биће суспендована ако не платите казну на https://example.invalid/rs/a2",
      "Evidentirana je neplaćena putarina. Izbegnite administrativnu taksu od 35%: https://example.invalid/rs/a3",
      "Министарство саобраћаја: прекршај је унет у систем. Платите у року од 24 сата: https://example.invalid/rs/a4",
      "Vaša vozačka dozvola može biti privremeno povučena. Izmirite dug na https://example.invalid/rs/a5",
    ],
  },
  {
    id: "rs-post-customs",
    country: "RS",
    sourceUrl: "https://www.cert.rs/files/shares/Smising%20i%20razvoj%20SMS%20prevara%20lat.pdf",
    texts: [
      "Pošta Srbije: Paket je zadržan zbog carinske naknade od 180 dinara. Platite na https://example.invalid/rs/b1",
      "Ваша пошиљка подлеже царинама. Унесите адресу и картицу за наставак испоруке: https://example.invalid/rs/b2",
      "Dostava nije uspela zbog netačnog poštanskog broja. Ispravite podatke: https://example.invalid/rs/b3",
      "Paket se vraća pošiljaocu večeras. Zakažite novu isporuku uz uplatu na https://example.invalid/rs/b4",
      "Пошиљка чека у складишту. Потврдите адресу и платите трошкове слања: https://example.invalid/rs/b5",
    ],
  },
  {
    id: "rs-mobile-reward",
    country: "RS",
    sourceUrl: "https://www.nbs.rs/sr/scripts/showcontent/index.html?id=20711",
    texts: [
      "Vaših 9.260 poena kod mobilnog operatera ističe danas. Izaberite nagradu: https://example.invalid/rs/c1",
      "Čestitamo, bodovi su dovoljni za novi telefon. Platite dostavu karticom na https://example.invalid/rs/c2",
      "Program lojalnosti: preuzmite besplatne slušalice i unesite CVV na https://example.invalid/rs/c3",
      "Poeni će biti obrisani u ponoć. Zamenite ih za nagradu putem https://example.invalid/rs/c4",
      "Mobilni operator vas je izabrao za poklon. Potvrdite adresu i karticu: https://example.invalid/rs/c5",
    ],
  },
  {
    id: "rs-account-code",
    country: "RS",
    sourceUrl: "https://www.cert.rs/rs/obavestenje/1513-Aktuelna-fi%C5%A1ing-kampanja-usmerena-na-korisnike-aplikacije-WhatsApp.html",
    texts: [
      "WhatsApp podrška: nalog je označen kao robot. Pošaljite nam SMS kod da sprečite blokadu.",
      "Vaš Viber profil će biti ugašen. Odgovorite verifikacionim kodom koji upravo stiže.",
      "Bezbednosna provera nije završena. Prosledite šestocifreni kod administratoru naloga.",
      "Primećena je prijava sa novog uređaja. Potvrdite da ste to vi slanjem jednokratnog koda.",
      "Telegram nalog je privremeno zaključan. Pošaljite kod za otključavanje u ovoj poruci.",
    ],
  },
  {
    id: "rs-job-investment",
    country: "RS",
    sourceUrl: "https://www.cert.rs/rs/obavestenja.html",
    texts: [
      "Nudimo posao od kuće uz dnevnu zaradu 12.000 dinara. Uplatite 2.000 za aktivaciju zadataka.",
      "Izabrani ste za online posao ocenjivanja proizvoda. Javite se menadžeru na Telegramu.",
      "Garantovana zarada od kripto trgovine. Početni depozit je samo 50 EUR, registrujte se danas.",
      "Zaradite proviziju lajkovanjem videa. Za viši nivo zadataka prvo izvršite uplatu.",
      "Vaš investicioni račun ima dobit za povlačenje. Platite poresku naknadu da oslobodite sredstva.",
    ],
  },
];

export const bhsIndependentChallengeSamples: BhsChallengeSample[] = families.flatMap((family) =>
  family.texts.map((text, index) => ({
    id: `bhs-challenge-${family.id}-${String(index + 1).padStart(2, "0")}`,
    country: family.country,
    family: family.id,
    text,
    sourceUrl: family.sourceUrl,
    provenance: "source-grounded-synthetic" as const,
  }))
);

if (bhsIndependentChallengeSamples.length !== 75) {
  throw new Error(`Expected 75 BHS challenge samples, got ${bhsIndependentChallengeSamples.length}.`);
}
