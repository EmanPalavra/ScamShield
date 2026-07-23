"use client";

import type { ReactNode } from "react";
import { useLanguage } from "./i18n";

type InfoPage = "how-it-works" | "methodology" | "privacy" | "limitations";
type ContentLocale = "bs" | "hr" | "sr" | "de" | "es" | "fr" | "nl";
type LocalizedSection = { label: string; title: string; body: string };

const content: Record<ContentLocale, Record<InfoPage, LocalizedSection[]>> = {
  bs: {
    "how-it-works": [
      { label: "Unos", title: "Cijela poruka se analizira kao jedan razgovor", body: "ScamShield normalizuje tekst i traži kombinacije hitnosti, prijetnji, zahtjeva za podacima, plaćanja, nagrada, autoriteta i prikrivanja na podržanim jezicima." },
      { label: "Struktura", title: "Link se raščlanjuje bez otvaranja stranice", body: "Provjeravaju se stvarna domena, HTTPS, IP adrese, Punycode, skraćivači, dubina putanje i parametri. Sumnjiva stranica se ne izvršava u vašem pregledniku." },
      { label: "Reputacija", title: "Nezavisni izvori dodaju aktuelne podatke", body: "Google Safe Browsing, RDAP i opcionalni VirusTotal rade s vremenskim ograničenjem. Nedostupan izvor se prikazuje kao nedostupan, a ne kao siguran." },
      { label: "Odluka", title: "Dokazi postaju jasna preporuka", body: "Rezultat prikazuje rizik, pronađene signale, analizirane URL-ove i konkretne sljedeće korake. Nizak rizik nije garancija sigurnosti." },
    ],
    methodology: [
      { label: "Pravila", title: "Svako upozorenje ima vidljiv razlog", body: "Ponderisana pravila pokrivaju krađu pristupnih podataka, lažne naplate, dostavu, kripto prevare, nagradne i poslovne prevare, prevare na oglasnicima i lažno predstavljanje." },
      { label: "Kontekst", title: "Kombinacije vrijede više od pojedinačnih riječi", body: "Jedna riječ je slab signal. Rizik raste kada se zajedno pojave hitnost, osjetljivi podaci, plaćanje, posljedice, autoritet, tajnost ili sumnjiv link." },
      { label: "Izvori", title: "Vanjske provjere dodaju dokaz, ne pretpostavku", body: "Reputacijski izvori se izvršavaju paralelno. Čist rezultat znači samo da taj izvor u tom trenutku nije vratio poznatu prijetnju." },
      { label: "Ocjena", title: "Tri nivoa rizika izbjegavaju lažnu sigurnost", body: "Low označava da nema jakog potvrđenog signala, Medium traži nezavisnu provjeru, a High znači da ne treba klikati, odgovarati, plaćati ili dijeliti podatke." },
    ],
    privacy: [
      { label: "Unos", title: "Pošaljite samo ono što je potrebno za procjenu", body: "Uklonite lozinke, jednokratne kodove, linkove za oporavak, identifikacijske brojeve i privatne interne URL-ove prije skeniranja." },
      { label: "Čuvanje", title: "Poruke se namjerno ne spremaju u bazu aplikacije", body: "Trenutna aplikacija nema korisničke profile ni historiju skeniranja. Rezultat se vraća trenutnoj sesiji preglednika." },
      { label: "Dijeljenje", title: "Vanjski servisi dobijaju samo podatke potrebne za provjeru", body: "Javni URL ili domena mogu biti poslani reputacijskim servisima. Privatne adrese, ugrađene vjerodajnice i osjetljivi tokenizirani URL-ovi se blokiraju." },
      { label: "Saglasnost", title: "Nova VirusTotal analiza se nikada ne pokreće automatski", body: "Slanje URL-a na novu javnu analizu zahtijeva jasno upozorenje i izričitu saglasnost. Privatne ili jednokratne linkove ne treba slati." },
    ],
    limitations: [
      { label: "Nove prijetnje", title: "Potpuno nova prevara možda još nema reputaciju", body: "Nove ili ciljane kampanje mogu proći bez upozorenja jer ih javni izvori još nisu vidjeli. Bez izvještaja ne znači sigurno." },
      { label: "Kontekst", title: "Rezultat zavisi od teksta i URL-ova koje unesete", body: "ScamShield ne može potvrditi identitet pošiljaoca, pregledati priloge, QR slike, cijeli razgovor ili ono što se desi nakon prijave." },
      { label: "Greške", title: "Pravila mogu pretjerano reagovati ili propustiti nov obrazac", body: "Legitimne poruke ponekad koriste hitan jezik, dok napadači mogu izbjegavati poznate fraze. Rezultat je pomoć pri odluci, ne pravna presuda." },
      { label: "Dostupnost", title: "Pokrivenost vanjskih izvora može biti nepotpuna", body: "Google, RDAP i VirusTotal mogu dosegnuti vremensko ograničenje ili kvotu i vratiti djelimičan rezultat. Nedostupna provjera ne poništava lokalnu analizu poruke." },
    ],
  },
  hr: {
    "how-it-works": [
      { label: "Unos", title: "Cijela se poruka analizira kao jedinstvena cjelina", body: "ScamShield normalizira tekst i u podržanim jezicima traži kombinacije hitnosti, prijetnji, zahtjeva za vjerodajnicama, plaćanja, nagrada, autoriteta i prikrivanja." },
      { label: "Struktura", title: "Poveznica se raščlanjuje bez otvaranja stranice", body: "Provjeravaju se stvarna domena, HTTPS, IP adrese, Punycode, skraćene poveznice, dubina putanje i parametri. Sumnjiva se stranica ne izvršava u vašem pregledniku." },
      { label: "Reputacija", title: "Neovisni izvori dodaju aktualne podatke", body: "Google Safe Browsing, RDAP i izborni VirusTotal imaju vremensko ograničenje. Nedostupan izvor prikazuje se kao nedostupan, a ne kao siguran." },
      { label: "Odluka", title: "Dokazi se pretvaraju u jasnu preporuku", body: "Rezultat prikazuje rizik, pronađene signale, analizirane URL-ove i konkretne sljedeće korake. Nizak rizik nije jamstvo sigurnosti." },
    ],
    methodology: [
      { label: "Pravila", title: "Svako upozorenje ima vidljiv razlog", body: "Ponderirana pravila obuhvaćaju krađu vjerodajnica, lažne naplate, dostavu, kriptoprevare, nagradne i poslovne prijevare, prijevare na oglasnicima te lažno predstavljanje." },
      { label: "Kontekst", title: "Kombinacije vrijede više od pojedinačnih riječi", body: "Jedna je riječ slab signal. Rizik raste kada se zajedno pojave hitnost, osjetljivi podaci, plaćanje, posljedice, autoritet, tajnost ili sumnjiva poveznica." },
      { label: "Izvori", title: "Vanjske provjere dodaju dokaz, a ne pretpostavku", body: "Reputacijski izvori provjeravaju se usporedno. Čist rezultat znači samo da određeni izvor u tom trenutku nije prijavio poznatu prijetnju." },
      { label: "Procjena", title: "Tri razine rizika sprječavaju lažan osjećaj sigurnosti", body: "Niska razina znači da nema snažnog potvrđenog signala, srednja zahtijeva neovisnu provjeru, a visoka znači da ne treba klikati, odgovarati, plaćati ni dijeliti podatke." },
    ],
    privacy: [
      { label: "Unos", title: "Pošaljite samo ono što je potrebno za procjenu", body: "Prije skeniranja uklonite lozinke, jednokratne kodove, poveznice za oporavak, identifikacijske brojeve i privatne interne URL-ove." },
      { label: "Pohrana", title: "Poruke se ne spremaju u bazu podataka aplikacije", body: "Trenutačna aplikacija nema korisničke profile ni povijest skeniranja. Rezultat se vraća trenutačnoj sesiji preglednika." },
      { label: "Dijeljenje", title: "Vanjske usluge primaju samo podatke potrebne za provjeru", body: "Javni URL ili domena mogu se poslati reputacijskim uslugama. Privatne adrese, ugrađene vjerodajnice i osjetljivi tokenizirani URL-ovi blokiraju se." },
      { label: "Privola", title: "Nova VirusTotal analiza nikada se ne pokreće automatski", body: "Slanje URL-a na novu javnu analizu zahtijeva jasno upozorenje i izričitu privolu. Privatne ili jednokratne poveznice ne treba slati." },
    ],
    limitations: [
      { label: "Nove prijetnje", title: "Potpuno nova prijevara možda još nema reputacijske podatke", body: "Nove ili ciljane kampanje mogu proći bez upozorenja jer ih javni izvori još nisu zabilježili. Izostanak izvještaja ne znači da je sadržaj siguran." },
      { label: "Kontekst", title: "Rezultat ovisi o tekstu i URL-ovima koje unesete", body: "ScamShield ne može potvrditi identitet pošiljatelja niti pregledati privitke, QR kodove, cijeli razgovor ili ono što se dogodi nakon prijave." },
      { label: "Pogreške", title: "Pravila mogu pretjerano reagirati ili propustiti novi obrazac", body: "Legitimne poruke ponekad koriste hitan jezik, dok napadači mogu izbjegavati poznate izraze. Rezultat je pomoć pri odluci, a ne pravna presuda." },
      { label: "Dostupnost", title: "Pokrivenost vanjskih izvora može biti nepotpuna", body: "Google, RDAP i VirusTotal mogu dosegnuti vremensko ograničenje ili kvotu te vratiti djelomičan rezultat. Nedostupna provjera ne poništava lokalnu analizu poruke." },
    ],
  },
  sr: {
    "how-it-works": [
      { label: "Unos", title: "Cela poruka se analizira kao jedna celina", body: "ScamShield normalizuje tekst i na podržanim jezicima traži kombinacije hitnosti, pretnji, zahteva za pristupnim podacima, plaćanja, nagrada, autoriteta i prikrivanja." },
      { label: "Struktura", title: "Veza se raščlanjuje bez otvaranja stranice", body: "Proveravaju se stvarni domen, HTTPS, IP adrese, Punycode, skraćene veze, dubina putanje i parametri. Sumnjiva stranica se ne izvršava u vašem pregledaču." },
      { label: "Reputacija", title: "Spoljni izvori dodaju aktuelne podatke", body: "Google Safe Browsing, RDAP i opcioni VirusTotal imaju vremensko ograničenje. Nedostupan izvor se prikazuje kao nedostupan, a ne kao bezbedan." },
      { label: "Odluka", title: "Dokazi postaju jasna preporuka", body: "Rezultat prikazuje rizik, pronađene signale, analizirane URL adrese i konkretne sledeće korake. Nizak rizik nije garancija bezbednosti." },
    ],
    methodology: [
      { label: "Pravila", title: "Svako upozorenje ima vidljiv razlog", body: "Ponderisana pravila obuhvataju krađu pristupnih podataka, lažne naplate, dostavu, kripto prevare, nagradne i poslovne prevare, prevare na oglasima i lažno predstavljanje." },
      { label: "Kontekst", title: "Kombinacije znače više od pojedinačnih reči", body: "Jedna reč je slab signal. Rizik raste kada se zajedno pojave hitnost, osetljivi podaci, plaćanje, posledice, autoritet, tajnost ili sumnjiva veza." },
      { label: "Izvori", title: "Spoljne provere dodaju dokaz, a ne pretpostavku", body: "Izvori reputacije proveravaju se paralelno. Čist rezultat znači samo da taj izvor u tom trenutku nije prijavio poznatu pretnju." },
      { label: "Ocena", title: "Tri nivoa rizika sprečavaju lažan osećaj sigurnosti", body: "Nizak nivo znači da nema jakog potvrđenog signala, srednji zahteva nezavisnu proveru, a visok znači da ne treba kliknuti, odgovoriti, platiti niti deliti podatke." },
    ],
    privacy: [
      { label: "Unos", title: "Pošaljite samo ono što je potrebno za procenu", body: "Pre skeniranja uklonite lozinke, jednokratne kodove, veze za oporavak, identifikacione brojeve i privatne interne URL adrese." },
      { label: "Čuvanje", title: "Poruke se ne čuvaju u bazi podataka aplikacije", body: "Trenutna aplikacija nema korisničke profile ni istoriju skeniranja. Rezultat se vraća trenutnoj sesiji pregledača." },
      { label: "Deljenje", title: "Spoljni servisi dobijaju samo podatke potrebne za proveru", body: "Javna URL adresa ili domen mogu biti poslati servisima za proveru reputacije. Privatne adrese, ugrađeni pristupni podaci i osetljive tokenizovane URL adrese se blokiraju." },
      { label: "Saglasnost", title: "Nova VirusTotal analiza se nikada ne pokreće automatski", body: "Slanje URL adrese na novu javnu analizu zahteva jasno upozorenje i izričitu saglasnost. Privatne ili jednokratne veze ne treba slati." },
    ],
    limitations: [
      { label: "Nove pretnje", title: "Potpuno nova prevara možda još nema podatke o reputaciji", body: "Nove ili ciljane kampanje mogu proći bez upozorenja jer ih javni izvori još nisu zabeležili. Odsustvo izveštaja ne znači da je sadržaj bezbedan." },
      { label: "Kontekst", title: "Rezultat zavisi od teksta i URL adresa koje unesete", body: "ScamShield ne može potvrditi identitet pošiljaoca niti pregledati priloge, QR kodove, ceo razgovor ili ono što se dogodi nakon prijave." },
      { label: "Greške", title: "Pravila mogu preterano reagovati ili propustiti novi obrazac", body: "Legitimne poruke ponekad koriste hitan jezik, dok napadači mogu izbegavati poznate izraze. Rezultat je pomoć pri odluci, a ne pravna presuda." },
      { label: "Dostupnost", title: "Pokrivenost spoljnih izvora može biti nepotpuna", body: "Google, RDAP i VirusTotal mogu dostići vremensko ograničenje ili kvotu i vratiti delimičan rezultat. Nedostupna provera ne poništava lokalnu analizu poruke." },
    ],
  },
  de: {
    "how-it-works": [
      { label: "Eingabe", title: "Die vollständige Nachricht wird als ein Gespräch analysiert", body: "ScamShield normalisiert den Text und sucht in unterstützten Sprachen nach Kombinationen aus Dringlichkeit, Drohungen, Zugangsdaten, Zahlungen, Belohnungen, Autorität und Verschleierung." },
      { label: "Struktur", title: "Der Link wird analysiert, ohne die Seite zu öffnen", body: "Geprüft werden echte Domain, HTTPS, IP-Adressen, Punycode, Kurzlinks, Pfadtiefe und Parameter. Die verdächtige Website wird nicht im Browser ausgeführt." },
      { label: "Reputation", title: "Unabhängige Quellen ergänzen aktuelle Hinweise", body: "Google Safe Browsing, RDAP und optional VirusTotal laufen mit Zeitlimit. Eine nicht verfügbare Quelle wird nicht als sauber interpretiert." },
      { label: "Entscheidung", title: "Belege werden zu einer klaren Empfehlung", body: "Der Bericht zeigt Risiko, gefundene Signale, geprüfte URLs und konkrete nächste Schritte. Ein niedriges Risiko ist keine Sicherheitsgarantie." },
    ],
    methodology: [
      { label: "Regeln", title: "Jede Warnung hat einen sichtbaren Grund", body: "Gewichtete Regeln erkennen Phishing, falsche Abbuchungen, Lieferbetrug, Krypto- und Gewinnversprechen, Jobbetrug, Marktplatzbetrug und Identitätsvortäuschung." },
      { label: "Kontext", title: "Kombinationen zählen mehr als einzelne Wörter", body: "Ein einzelnes Wort ist ein schwaches Signal. Das Risiko steigt, wenn Dringlichkeit, sensible Daten, Zahlung, Konsequenzen, Autorität, Geheimhaltung oder ein verdächtiger Link zusammenkommen." },
      { label: "Quellen", title: "Externe Prüfungen liefern Belege statt Annahmen", body: "Reputationsdienste laufen parallel. Ein sauberes Ergebnis bedeutet nur, dass dieser Dienst zu diesem Zeitpunkt keine bekannte Bedrohung gemeldet hat." },
      { label: "Bewertung", title: "Drei Risikostufen vermeiden falsche Sicherheit", body: "Niedrig bedeutet keine starke Bestätigung, Mittel verlangt unabhängige Prüfung und Hoch bedeutet: nicht klicken, antworten, zahlen oder Daten teilen." },
    ],
    privacy: [
      { label: "Eingabe", title: "Senden Sie nur, was für die Prüfung nötig ist", body: "Entfernen Sie Passwörter, Einmalcodes, Wiederherstellungslinks, Identitätsnummern und private interne URLs vor dem Scan." },
      { label: "Speicherung", title: "Nachrichten werden nicht in einer Anwendungsdatenbank gespeichert", body: "Die aktuelle Anwendung führt keine Benutzerprofile oder Scanverläufe. Das Ergebnis wird an die aktuelle Browsersitzung zurückgegeben." },
      { label: "Weitergabe", title: "Externe Dienste erhalten nur die nötigen Daten", body: "Öffentliche URLs oder Domains können an Reputationsdienste gesendet werden. Private Adressen, eingebettete Zugangsdaten und sensible Token-URLs werden blockiert." },
      { label: "Zustimmung", title: "Eine neue VirusTotal-Analyse startet nie automatisch", body: "Eine neue öffentliche URL-Analyse benötigt eine deutliche Warnung und ausdrückliche Zustimmung. Private oder einmalige Links sollten nicht gesendet werden." },
    ],
    limitations: [
      { label: "Neue Angriffe", title: "Ein neuer Betrugsversuch hat möglicherweise noch keine Reputation", body: "Neue oder gezielte Kampagnen können ohne Warnung bleiben, weil öffentliche Quellen sie noch nicht kennen. Ein fehlender Bericht bedeutet nicht, dass der Inhalt sicher ist." },
      { label: "Kontext", title: "Das Ergebnis ist auf Ihre Eingabe begrenzt", body: "ScamShield kann Absender nicht authentifizieren und keine Anhänge, QR-Bilder, vollständigen Gespräche oder Vorgänge nach einer Anmeldung prüfen." },
      { label: "Fehler", title: "Regeln können überreagieren oder neue Muster übersehen", body: "Legitime Nachrichten nutzen manchmal Dringlichkeit, während Angreifer bekannte Formulierungen vermeiden. Das Ergebnis ist Entscheidungshilfe, kein Rechtsurteil." },
      { label: "Verfügbarkeit", title: "Externe Abdeckung kann unvollständig sein", body: "Google, RDAP und VirusTotal können Zeitüberschreitungen, Quoten oder Teilergebnisse haben. Eine fehlende Prüfung löscht die lokale Analyse nicht." },
    ],
  },
  es: {
    "how-it-works": [
      { label: "Entrada", title: "El mensaje completo se analiza como una conversación", body: "ScamShield normaliza el texto y busca combinaciones de urgencia, amenazas, credenciales, pagos, premios, autoridad y ocultación en los idiomas compatibles." },
      { label: "Estructura", title: "El enlace se analiza sin abrir la página", body: "Se comprueban el dominio real, HTTPS, direcciones IP, Punycode, acortadores, profundidad de ruta y parámetros. El sitio sospechoso no se ejecuta en el navegador." },
      { label: "Reputación", title: "Fuentes independientes añaden información actual", body: "Google Safe Browsing, RDAP y VirusTotal opcional funcionan con límite de tiempo. Una fuente no disponible nunca se interpreta como limpia." },
      { label: "Decisión", title: "La evidencia se convierte en una recomendación clara", body: "El informe muestra el riesgo, las señales, las URL revisadas y los siguientes pasos. Un riesgo bajo no garantiza seguridad." },
    ],
    methodology: [
      { label: "Reglas", title: "Cada advertencia tiene una razón visible", body: "Las reglas ponderadas cubren phishing, cargos falsos, entregas, criptoestafas, premios, empleo, mercados y suplantación." },
      { label: "Contexto", title: "Las combinaciones importan más que palabras aisladas", body: "Una palabra es una señal débil. El riesgo aumenta al combinar urgencia, datos sensibles, pagos, consecuencias, autoridad, secreto o un enlace sospechoso." },
      { label: "Fuentes", title: "Las comprobaciones externas aportan evidencia, no suposiciones", body: "Los proveedores se consultan en paralelo. Un resultado limpio solo significa que esa fuente no devolvió una amenaza conocida en ese momento." },
      { label: "Puntuación", title: "Tres niveles evitan una falsa sensación de seguridad", body: "Bajo significa que no se confirmó una señal fuerte; Medio exige verificación independiente; Alto indica no hacer clic, responder, pagar ni compartir datos." },
    ],
    privacy: [
      { label: "Entrada", title: "Envíe solo lo necesario para evaluar el riesgo", body: "Elimine contraseñas, códigos de un solo uso, enlaces de recuperación, números de identidad y URL internas privadas." },
      { label: "Conservación", title: "Los mensajes no se guardan deliberadamente en una base de datos", body: "La aplicación no mantiene perfiles de usuario ni historial de análisis. El resultado vuelve a la sesión actual del navegador." },
      { label: "Proveedores", title: "Los servicios externos reciben solo los datos necesarios", body: "Las URL o dominios públicos pueden enviarse a servicios de reputación. Se bloquean direcciones privadas, credenciales y URL con tokens sensibles." },
      { label: "Consentimiento", title: "Un nuevo análisis de VirusTotal nunca se inicia automáticamente", body: "Un nuevo análisis público requiere una advertencia clara y consentimiento explícito. No envíe enlaces privados o de un solo uso." },
    ],
    limitations: [
      { label: "Ataques nuevos", title: "Una estafa nueva puede no tener datos de reputación", body: "Las campañas nuevas o dirigidas pueden no generar alertas porque las fuentes públicas aún no las conocen. La ausencia de un informe no significa que el contenido sea seguro." },
      { label: "Contexto", title: "El resultado se limita al contenido enviado", body: "ScamShield no autentica al remitente ni revisa adjuntos, QR, conversaciones completas o lo que ocurre después de iniciar sesión." },
      { label: "Errores", title: "Las reglas pueden reaccionar de más u omitir patrones nuevos", body: "Los mensajes legítimos pueden usar urgencia y los atacantes evitar frases conocidas. El resultado orienta una decisión, no es un veredicto legal." },
      { label: "Disponibilidad", title: "La cobertura externa puede ser incompleta", body: "Google, RDAP y VirusTotal pueden agotar tiempo, cuota o devolver datos parciales. Una comprobación ausente no elimina el análisis local." },
    ],
  },
  fr: {
    "how-it-works": [
      { label: "Entrée", title: "Le message complet est analysé comme une conversation", body: "ScamShield normalise le texte et recherche des combinaisons d’urgence, de menaces, d’identifiants, de paiements, de récompenses, d’autorité et de masquage." },
      { label: "Structure", title: "Le lien est analysé sans ouvrir la page", body: "Le domaine réel, HTTPS, les adresses IP, Punycode, les raccourcisseurs, le chemin et les paramètres sont vérifiés. Le site suspect n’est pas exécuté dans le navigateur." },
      { label: "Réputation", title: "Des sources indépendantes ajoutent des informations actuelles", body: "Google Safe Browsing, RDAP et VirusTotal optionnel fonctionnent avec un délai limité. Une source indisponible n’est jamais considérée comme sûre." },
      { label: "Décision", title: "Les preuves deviennent une recommandation claire", body: "Le rapport présente le risque, les signaux, les URL inspectées et les prochaines étapes. Un risque faible ne garantit pas la sécurité." },
    ],
    methodology: [
      { label: "Règles", title: "Chaque avertissement a une raison visible", body: "Les règles pondérées couvrent le phishing, les faux débits, la livraison, la crypto, les prix, l’emploi, les marchés et l’usurpation." },
      { label: "Contexte", title: "Les combinaisons comptent plus que les mots isolés", body: "Un mot isolé est un signal faible. Le risque augmente lorsque urgence, données sensibles, paiement, conséquences, autorité, secret ou lien suspect apparaissent ensemble." },
      { label: "Sources", title: "Les contrôles externes ajoutent des preuves, pas des suppositions", body: "Les fournisseurs sont interrogés en parallèle. Un résultat propre signifie seulement que cette source n’a signalé aucune menace connue à cet instant." },
      { label: "Score", title: "Trois niveaux évitent une fausse impression de sécurité", body: "Faible signifie qu’aucun signal fort n’est confirmé, Moyen exige une vérification indépendante et Élevé signifie qu’il ne faut ni cliquer, ni répondre, ni payer, ni partager de données." },
    ],
    privacy: [
      { label: "Entrée", title: "Envoyez uniquement ce qui est nécessaire", body: "Supprimez les mots de passe, codes à usage unique, liens de récupération, numéros d’identité et URL internes privées." },
      { label: "Conservation", title: "Les messages ne sont pas volontairement stockés dans une base", body: "L’application actuelle ne conserve ni profil utilisateur ni historique d’analyse. Le résultat est renvoyé à la session actuelle." },
      { label: "Fournisseurs", title: "Les services externes reçoivent uniquement les données nécessaires", body: "Les URL ou domaines publics peuvent être transmis aux services de réputation. Les adresses privées, identifiants et URL à jeton sensible sont bloqués." },
      { label: "Consentement", title: "Une nouvelle analyse VirusTotal ne démarre jamais automatiquement", body: "Une nouvelle analyse publique exige un avertissement clair et un consentement explicite. N’envoyez pas de liens privés ou à usage unique." },
    ],
    limitations: [
      { label: "Nouvelles attaques", title: "Une nouvelle arnaque peut ne pas avoir de données de réputation", body: "Les campagnes nouvelles ou ciblées peuvent rester sans alerte car les sources publiques ne les connaissent pas encore. L’absence de rapport ne signifie pas que le contenu est sûr." },
      { label: "Contexte", title: "Le résultat est limité au contenu fourni", body: "ScamShield ne peut pas authentifier l’expéditeur ni inspecter les pièces jointes, QR, conversations complètes ou actions après connexion." },
      { label: "Erreurs", title: "Les règles peuvent sur-réagir ou manquer un nouveau schéma", body: "Les messages légitimes utilisent parfois l’urgence et les attaquants évitent les formulations connues. Le résultat guide une décision, sans valeur juridique." },
      { label: "Disponibilité", title: "La couverture externe peut être incomplète", body: "Google, RDAP et VirusTotal peuvent expirer, atteindre un quota ou renvoyer des données partielles. Un contrôle absent n’efface pas l’analyse locale." },
    ],
  },
  nl: {
    "how-it-works": [
      { label: "Invoer", title: "Het volledige bericht wordt als één gesprek geanalyseerd", body: "ScamShield normaliseert tekst en zoekt in ondersteunde talen naar combinaties van urgentie, dreiging, inloggegevens, betaling, beloning, autoriteit en versluiering." },
      { label: "Structuur", title: "De link wordt ontleed zonder de pagina te openen", body: "Het echte domein, HTTPS, IP-adressen, Punycode, verkorters, paddiepte en parameters worden gecontroleerd. De verdachte site wordt niet in de browser uitgevoerd." },
      { label: "Reputatie", title: "Onafhankelijke bronnen voegen actuele informatie toe", body: "Google Safe Browsing, RDAP en optioneel VirusTotal werken met een tijdslimiet. Een onbeschikbare bron wordt nooit als schoon beschouwd." },
      { label: "Beslissing", title: "Bewijs wordt een duidelijke aanbeveling", body: "Het rapport toont risico, gevonden signalen, gecontroleerde URL’s en concrete vervolgstappen. Een laag risico is geen veiligheidsgarantie." },
    ],
    methodology: [
      { label: "Regels", title: "Elke waarschuwing heeft een zichtbare reden", body: "Gewogen regels herkennen phishing, valse afschrijvingen, bezorgfraude, crypto, prijzen, banen, marktplaatsfraude en imitatie." },
      { label: "Context", title: "Combinaties tellen zwaarder dan losse woorden", body: "Eén woord is een zwak signaal. Het risico stijgt wanneer urgentie, gevoelige gegevens, betaling, gevolgen, autoriteit, geheimhouding of een verdachte link samen voorkomen." },
      { label: "Bronnen", title: "Externe controles leveren bewijs, geen aannames", body: "Reputatiebronnen worden parallel gecontroleerd. Een schoon resultaat betekent alleen dat die bron op dat moment geen bekende dreiging meldde." },
      { label: "Score", title: "Drie risiconiveaus voorkomen schijnveiligheid", body: "Laag betekent geen sterk bevestigd signaal, Gemiddeld vereist onafhankelijke controle en Hoog betekent niet klikken, antwoorden, betalen of gegevens delen." },
    ],
    privacy: [
      { label: "Invoer", title: "Verstuur alleen wat nodig is voor de beoordeling", body: "Verwijder wachtwoorden, eenmalige codes, herstellinks, identiteitsnummers en privé-interne URL’s vóór de scan." },
      { label: "Bewaren", title: "Berichten worden niet bewust in een appdatabase opgeslagen", body: "De huidige app bewaart geen gebruikersprofielen of scangeschiedenis. Het resultaat gaat terug naar de huidige browsersessie." },
      { label: "Delen", title: "Externe diensten ontvangen alleen noodzakelijke gegevens", body: "Openbare URL’s of domeinen kunnen naar reputatiediensten gaan. Privéadressen, ingebouwde inloggegevens en gevoelige token-URL’s worden geblokkeerd." },
      { label: "Toestemming", title: "Een nieuwe VirusTotal-analyse start nooit automatisch", body: "Een nieuwe openbare analyse vereist een duidelijke waarschuwing en expliciete toestemming. Verstuur geen privé- of eenmalige links." },
    ],
    limitations: [
      { label: "Nieuwe dreigingen", title: "Een nieuwe vorm van fraude heeft mogelijk nog geen reputatiegegevens", body: "Nieuwe of gerichte campagnes kunnen zonder waarschuwing blijven omdat openbare bronnen ze nog niet kennen. Het ontbreken van een rapport betekent niet dat de inhoud veilig is." },
      { label: "Context", title: "Het resultaat is beperkt tot uw invoer", body: "ScamShield kan de afzender niet verifiëren en geen bijlagen, QR-afbeeldingen, volledige gesprekken of acties na het inloggen bekijken." },
      { label: "Fouten", title: "Regels kunnen overreageren of een nieuw patroon missen", body: "Legitieme berichten gebruiken soms urgentie en aanvallers vermijden bekende zinnen. Het resultaat helpt bij beslissen en is geen juridisch oordeel." },
      { label: "Beschikbaarheid", title: "Externe dekking kan onvolledig zijn", body: "Google, RDAP en VirusTotal kunnen time-outs, quota of gedeeltelijke resultaten hebben. Een ontbrekende controle wist de lokale analyse niet." },
    ],
  },
};

function contentLocale(locale: string): ContentLocale {
  return locale as ContentLocale;
}

export function LocalizedInfoContent({ page, sectionIds, children }: { page: InfoPage; sectionIds: string[]; children: ReactNode }) {
  const { locale } = useLanguage();
  if (locale === "en") return children;
  const sections = content[contentLocale(locale)][page];
  return sections.map((section, index) => (
    <section key={`${page}-${index}`} id={sectionIds[index]}>
      <div className="info-number"><span>{String(index + 1).padStart(2, "0")}</span><small>{section.label}</small></div>
      <div className="info-section-copy">
        <span className="info-section-label">{section.label}</span>
        <h2>{section.title}</h2>
        <p>{section.body}</p>
      </div>
    </section>
  ));
}
