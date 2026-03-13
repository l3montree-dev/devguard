---
cra:
  applies: true
  class: I
  conformity_assessment: self-declaration
  article: "27(1)"
  annex: "III/1"
license: AGPL-3.0
sbom:
  format: cyclonedx-1.4-json
  url: https://api.main.devguard.org/api/v1/organizations/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/artifacts/pkg%3Aoci%2Fdevguard%3Frepository_url%3Dghcr.io%2Fl3montree-dev%2Fdevguard/sbom.json/
security_contact: developer@l3montree.com
security_txt: https://l3montree.com/.well-known/security.txt
openssf_badge: https://www.bestpractices.dev/projects/8928
---

# Klassifizierung nach CRA

**Fällt das Projekt unter den CRA?** (Verweis auf Artikel 2):

Ja. DevGuard ist ein Software-Produkt mit digitalen Elementen im Sinne des CRA (Artikel 2). Es wird von l3montree cybersecurity entwickelt und kommerziell vertrieben bzw. im Rahmen von Dienstleistungen eingesetzt. Als Open-Source-Software (AGPL-3.0) mit gewerblichem Hintergrund gilt die Ausnahmeregelung für rein nicht-kommerzielle Open-Source-Projekte (Artikel 2(5)) nicht.

**Produktklasse** (Klasse I / Klasse II):

Klasse I (gemäß Anhang III, Abschnitt 1)

**Begründung**:

DevGuard ist eine Vulnerability-Management- und Software-Supply-Chain-Sicherheitsplattform. Das Produkt fällt unter Klasse I, da es Sicherheitsfunktionen zur Schwachstellenerkennung, -bewertung und -verwaltung bereitstellt, die unter „Security information and event management" (SIEM) im Sinne des Anhang III einzuordnen sind.

DevGuard erfüllt keine Funktionen, die eine Einstufung als Klasse II erfordern würden (z. B. Betriebssystem-Kernel, Hypervisoren, Firewalls, Intrusion-Detection/-Prevention-Systeme, industrielle Steuerungssysteme). Es handelt sich um ein Developer-Tool für Sicherheitsverantwortliche und Entwicklungsteams zur Verwaltung von Schwachstellen im Softwareentwicklungsprozess.

Als Klasse-I-Produkt reicht eine **Selbsterklärung** (Artikel 27(1)) zur Konformitätsbewertung aus.
