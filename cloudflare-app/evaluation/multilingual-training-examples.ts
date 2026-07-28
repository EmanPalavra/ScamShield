export interface MultilingualTrainingSample {
  id: string;
  text: string;
  label: 0 | 1;
  source: "synthetic-multilingual-authority-derived" | "synthetic-multilingual-hard-negative";
}

interface LanguageMaterial {
  code: string;
  scams: string[];
  legitimate: string[];
}

const materials: LanguageMaterial[] = [
  {
    code: "de",
    scams: [
      "Sparkasse: Ihre Banking-App Registrierung läuft bald ab. Erneuern Sie den Zugang",
      "Deutsche Bank: Ihr photoTAN-Zugang wurde eingeschränkt. Bestätigen Sie Ihre Angaben",
      "DHL: Ihr Paket liegt im Sortierzentrum. Zahlen Sie die ausstehende Zollgebühr",
      "Deutsche Post: Die Zustellung ist fehlgeschlagen. Aktualisieren Sie Ihre Adresse",
      "Sie haben einen unbezahlten Strafzettel. Begleichen Sie den Betrag umgehend",
      "Hallo Mama, mein Handy ist kaputt. Das ist meine neue Nummer. Schreib mir auf WhatsApp",
      "Eine unbekannte Abbuchung wurde erkannt. Wenn Sie das nicht waren, prüfen Sie die Transaktion",
      "Finanzamt: Ihre Rückerstattung wartet. Bestätigen Sie Ihre Bankverbindung",
      "Ihr Konto wird heute gesperrt. Verifizieren Sie Passwort und Sicherheitscode",
      "Kaufen Sie Gutscheinkarten und senden Sie die Codes sofort an Ihren Geschäftsführer",
    ],
    legitimate: [
      "Ihre Kartenzahlung wurde erfolgreich ausgeführt. Sie müssen nichts unternehmen.",
      "Ihre TAN ist nur für Ihre Anmeldung bestimmt. Geben Sie den Code niemals weiter.",
      "Das Paket wurde erfolgreich zugestellt.",
      "Die Sendung liegt in der vereinbarten Filiale zur Abholung bereit.",
      "Der Banktermin findet am Dienstag statt.",
      "Die Rechnung wurde bereits bezahlt.",
      "Es fallen keine weiteren Zollgebühren an.",
      "Meine neue Nummer ist im Familienchat gespeichert.",
      "Die Bank fragt niemals per Nachricht nach PIN oder Passwort.",
      "Ihre Adresse wurde wie beauftragt geändert.",
      "Der Dauerauftrag wurde wie geplant ausgeführt.",
      "Die Sicherheitsinformation dient nur Ihrer Kenntnis.",
    ],
  },
  {
    code: "bhs",
    scams: [
      "Banka: Vaš račun je privremeno blokiran. Potvrdite podatke za prijavu",
      "Vaša kartica je ograničena zbog sumnjive aktivnosti. Ažurirajte lične podatke",
      "Pošta: Pošiljka je zadržana. Platite carinsku naknadu",
      "Dostava paketa nije uspjela zbog nepotpune adrese. Potvrdite adresu",
      "Evidentirana je neplaćena kazna. Izmirite dug odmah",
      "Mama, telefon mi je pokvaren. Ovo je moj novi broj. Pošalji mi novac",
      "Zabilježena je nepoznata transakcija. Ako ovo niste vi, provjerite račun",
      "Porezna uprava: Povrat poreza čeka isplatu. Potvrdite bankovne podatke",
      "Račun će danas biti zaključan. Unesite lozinku i sigurnosni kod",
      "Direktor traži da hitno kupite poklon kartice i pošaljete kodove",
    ],
    legitimate: [
      "Kartična transakcija je uspješno izvršena. Nije potrebna nikakva radnja.",
      "Jednokratni kod je samo za vašu prijavu. Nikome ga ne dijelite.",
      "Paket je uspješno dostavljen.",
      "Pošiljka je spremna za preuzimanje u poslovnici.",
      "Termin u banci je zakazan za utorak.",
      "Račun je već plaćen.",
      "Nema dodatnih carinskih troškova.",
      "Moj novi broj je spremljen u porodičnoj grupi.",
      "Banka nikada ne traži PIN ili lozinku putem poruke.",
      "Adresa je promijenjena prema vašem zahtjevu.",
      "Trajni nalog je uredno izvršen.",
      "Sigurnosna obavijest je informativnog karaktera.",
    ],
  },
  {
    code: "fr",
    scams: [
      "Banque : votre accès mobile expire bientôt. Renouvelez votre inscription",
      "Votre carte est temporairement bloquée. Confirmez vos informations",
      "Votre colis est retenu au centre de tri. Payez les frais de douane",
      "La livraison a échoué à cause de votre adresse. Mettez-la à jour",
      "Une amende impayée a été enregistrée. Réglez-la immédiatement",
      "Bonjour maman, mon téléphone est cassé. Voici mon nouveau numéro. Écris-moi",
      "Une transaction inconnue a été détectée. Si ce n'est pas vous, vérifiez-la",
      "Impôts : votre remboursement est prêt. Confirmez vos coordonnées bancaires",
      "Votre compte sera suspendu aujourd'hui. Saisissez votre mot de passe et le code",
      "Achetez des cartes cadeaux et envoyez les codes au directeur immédiatement",
    ],
    legitimate: [
      "Votre paiement par carte a été effectué. Aucune action n'est requise.",
      "Ce code est réservé à votre connexion. Ne le partagez jamais.",
      "Votre colis a été livré avec succès.",
      "Le colis est disponible au point relais convenu.",
      "Votre rendez-vous bancaire est prévu mardi.",
      "La facture a déjà été réglée.",
      "Aucun frais de douane supplémentaire n'est dû.",
      "Mon nouveau numéro est enregistré dans le groupe familial.",
      "La banque ne demande jamais votre mot de passe par message.",
      "Votre adresse a été modifiée comme demandé.",
      "Le virement permanent a été exécuté normalement.",
      "Cette notification de sécurité est uniquement informative.",
    ],
  },
  {
    code: "nl",
    scams: [
      "Bank: uw mobiele registratie verloopt binnenkort. Vernieuw uw toegang",
      "Uw kaart is tijdelijk geblokkeerd. Bevestig uw gegevens",
      "Uw pakket ligt in het sorteercentrum. Betaal de douanekosten",
      "De bezorging is mislukt door een onjuist adres. Werk het adres bij",
      "Er staat een onbetaalde boete open. Betaal het bedrag onmiddellijk",
      "Hoi mam, mijn telefoon is kapot. Dit is mijn nieuwe nummer. Stuur mij een bericht",
      "Er is een onbekende transactie gevonden. Als u dit niet was, controleer deze",
      "Belastingdienst: uw teruggave staat klaar. Bevestig uw bankgegevens",
      "Uw rekening wordt vandaag geblokkeerd. Voer wachtwoord en code in",
      "Koop cadeaukaarten en stuur de codes onmiddellijk naar uw directeur",
    ],
    legitimate: [
      "Uw kaartbetaling is succesvol uitgevoerd. U hoeft niets te doen.",
      "Deze code is alleen voor uw aanmelding. Deel hem nooit met anderen.",
      "Uw pakket is succesvol bezorgd.",
      "De zending ligt klaar bij het afgesproken afhaalpunt.",
      "Uw afspraak bij de bank is dinsdag.",
      "De factuur is al betaald.",
      "Er zijn geen extra douanekosten.",
      "Mijn nieuwe nummer staat in de familiegroep.",
      "De bank vraagt nooit via een bericht om uw wachtwoord.",
      "Uw adres is op uw verzoek gewijzigd.",
      "De periodieke overschrijving is normaal uitgevoerd.",
      "Deze beveiligingsmelding is alleen ter informatie.",
    ],
  },
  {
    code: "es",
    scams: [
      "Banco: su registro móvil caduca pronto. Renueve el acceso",
      "Su tarjeta está bloqueada temporalmente. Confirme sus datos",
      "Su paquete está retenido en el centro de clasificación. Pague la tasa de aduana",
      "La entrega falló por una dirección incorrecta. Actualice la dirección",
      "Tiene una multa pendiente. Pague el importe inmediatamente",
      "Hola mamá, mi teléfono está roto. Este es mi nuevo número. Escríbeme",
      "Detectamos una transacción desconocida. Si no fue usted, revísela",
      "Agencia Tributaria: su devolución está lista. Confirme los datos bancarios",
      "Su cuenta será bloqueada hoy. Introduzca la contraseña y el código",
      "Compre tarjetas regalo y envíe los códigos al director inmediatamente",
    ],
    legitimate: [
      "El pago con tarjeta se realizó correctamente. No tiene que hacer nada.",
      "Este código es solo para iniciar sesión. Nunca lo comparta.",
      "El paquete fue entregado correctamente.",
      "El envío está disponible en el punto de recogida acordado.",
      "Su cita bancaria es el martes.",
      "La factura ya está pagada.",
      "No hay gastos de aduana adicionales.",
      "Mi nuevo número está guardado en el grupo familiar.",
      "El banco nunca solicita la contraseña por mensaje.",
      "Su dirección fue modificada según lo solicitado.",
      "La transferencia periódica se ejecutó normalmente.",
      "Este aviso de seguridad es únicamente informativo.",
    ],
  },
  {
    code: "en",
    scams: [
      "Bank: your mobile registration expires soon. Renew your access",
      "Your card is temporarily blocked. Confirm your details",
      "Your package is held at the sorting center. Pay the customs fee",
      "Delivery failed because of an incorrect address. Update the address",
      "You have an unpaid fine. Pay the amount immediately",
      "Hi Mum, my phone is broken. This is my new number. Message me",
      "An unknown transaction was detected. If this was not you, review it",
      "Tax office: your refund is ready. Confirm your bank details",
      "Your account will be locked today. Enter your password and security code",
      "Buy gift cards and send the codes to your manager immediately",
    ],
    legitimate: [
      "Your card payment completed successfully. No action is required.",
      "This code is only for your login. Never share it with anyone.",
      "Your package was delivered successfully.",
      "The shipment is ready at the agreed collection point.",
      "Your bank appointment is on Tuesday.",
      "The invoice has already been paid.",
      "There are no additional customs charges.",
      "My new number is saved in the family group.",
      "The bank never asks for a password by message.",
      "Your address was changed as requested.",
      "The scheduled transfer completed normally.",
      "This security notice is for information only.",
    ],
  },
];

const scamEndings = [
  ": https://secure-check.example",
  " — https://account-review.example",
  " — https://message-status.example",
  ": https://confirm-now.example",
];
const legitimateEndings = [
  "",
  ".",
  " [INFO]",
  " — OK",
  "\nRef: 2026",
];

function withoutDiacritics(text: string) {
  return text.normalize("NFD").replace(/\p{M}/gu, "").normalize("NFC");
}

function wordingVariants(text: string) {
  return [
    text,
    withoutDiacritics(text),
    text.toLocaleLowerCase(),
    text.replace(/[.:]/g, " ").replace(/\s+/g, " ").trim(),
    text.toLocaleUpperCase(),
  ];
}

export const multilingualTrainingExamples: MultilingualTrainingSample[] = materials.flatMap((material) => [
  ...material.scams.flatMap((text, messageIndex) =>
    scamEndings.flatMap((ending, endingIndex) =>
      wordingVariants(`${text}${ending}`).map((variant, variantIndex) => ({
        id: `${material.code}-scam-${messageIndex}-${endingIndex}-${variantIndex}`,
        text: variant,
        label: 1 as const,
        source: "synthetic-multilingual-authority-derived" as const,
      }))
    )
  ),
  ...material.legitimate.flatMap((text, messageIndex) =>
    legitimateEndings.map((ending, endingIndex) => ({
      id: `${material.code}-legitimate-${messageIndex}-${endingIndex}`,
      text: `${text}${ending}`,
      label: 0 as const,
      source: "synthetic-multilingual-hard-negative" as const,
    }))
  ),
]);
