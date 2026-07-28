export interface BhsHoldoutExample {
  id: string;
  text: string;
  sourceUrl: string;
  evidence: "verbatim";
}

/**
 * Short, verbatim excerpts that the cited bank, police, or national CERT
 * explicitly identified as fraudulent. These sources were added after the
 * production model and threshold had been locked.
 */
export const bhsHoldoutExamples: BhsHoldoutExample[] = [
  {
    id: "bhs-raiffeisen-locked-account",
    text: "Raiffeisen banka, sumnjiv pokušaj prijave, vaš račun je zaključan iz sigurnosnih razloga, pokušajte ovjeriti svih račun dolje navedenom vezom",
    sourceUrl: "https://app.raiffeisenbank.ba/en/node/4156",
    evidence: "verbatim",
  },
  {
    id: "bhs-mup-urgent-call",
    text: "Nazovi me hitno!",
    sourceUrl: "https://mup.gov.hr/print.aspx?id=183822&url=print",
    evidence: "verbatim",
  },
  {
    id: "bhs-certhr-child-vote",
    text: "Glasajte za moje dijete na natjecanju",
    sourceUrl: "https://www.cert.hr/upozorenje-oprezno-s-whatsapp-porukama/",
    evidence: "verbatim",
  },
  {
    id: "bhs-certhr-urgent-money",
    text: "Hitno mi pošalji ili posudi novac",
    sourceUrl: "https://www.cert.hr/upozorenje-oprezno-s-whatsapp-porukama/",
    evidence: "verbatim",
  },
  {
    id: "bhs-certhr-hep-unpaid",
    text: "Vaš posljednji račun nije plaćen…",
    sourceUrl: "https://www.cert.hr/upozorenje-napadaci-se-i-dalje-predstavljaju-kao-hep-te-prijete-iskljucivanjem-struje/",
    evidence: "verbatim",
  },
  {
    id: "bhs-certhr-hep-failed-payment",
    text: "Plaćanje vaše posljednje fakture nije uspjelo…",
    sourceUrl: "https://www.cert.hr/upozorenje-napadaci-se-i-dalje-predstavljaju-kao-hep-te-prijete-iskljucivanjem-struje/",
    evidence: "verbatim",
  },
];
