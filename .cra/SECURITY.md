---
security_contact: developer@l3montree.com
security_txt: https://l3montree.com/.well-known/security.txt
pgp_key: https://l3montree.com/developer@l3montree.com-0xA71508222B6168D5-pub.asc
vulnerability_reporting: https://github.com/l3montree-dev/devguard/security/advisories/new
security_advisories: https://github.com/l3montree-dev/devguard/security/advisories
response_times:
  critical:
    detection_hours: 24
    patch_hours: 72
  high:
    detection_days: 7
    patch_days: 30
  medium:
    detection_days: 30
    patch_days: 90
---

# Vulnerability Handling (Anhang I, Teil II + Artikel 10)

**Prozess zur Schwachstellenbehandlung**:

| Schweregrad (CVSS)   | Reaktionszeit (Erkennung)  | Patch-Frist | Verantwortlicher          |
|----------------------|----------------------------|-------------|---------------------------|
| Kritisch (9.0–10.0)  | 24 Stunden                 | 72 Stunden  | l3montree Security Team   |
| Hoch (7.0–8.9)       | 7 Tage                     | 30 Tage     | l3montree Security Team   |
| Mittel (4.0–6.9)     | 30 Tage                    | 90 Tage     | l3montree Security Team   |

DevGuard scannt sich selbst mit der eigenen `devguard-action` in der GitHub-CI/CD-Pipeline (`.github/workflows/devguard-scanner.yaml`). Dabei werden Abhängigkeiten, Container-Images und der Quellcode auf bekannte Schwachstellen (CVEs) geprüft. Erkannte Schwachstellen werden direkt in der DevGuard-Plattform erfasst und priorisiert bewertet (CVSS + EPSS + CISA KEV).

**Vulnerability Disclosure Program (VDP)**:

DevGuard betreibt ein Coordinated Vulnerability Disclosure Program (CVD). Schwachstellen können auf zwei Wegen gemeldet werden:

1. **GitHub Private Vulnerability Reporting**: Über die GitHub-Seite des Projekts ([Report a vulnerability](https://github.com/l3montree-dev/devguard/security/advisories/new)). Maintainer werden zunächst privat informiert. Nach einem Fix wird die Meldung veröffentlicht.

2. **Direktkontakt**: Meldung an das L3montree-Entwicklungsteam per E-Mail:
   - **Kontakt**: developer@l3montree.com
   - **PGP-Verschlüsselung**: https://l3montree.com/developer@l3montree.com-0xA71508222B6168D5-pub.asc
   - **Canonical security.txt**: https://l3montree.com/.well-known/security.txt

Das Team strebt an, Sicherheitspatches innerhalb einer Woche bereitzustellen. Meldende Personen können auf Wunsch als Finder genannt werden.

**Versionsrichtlinie**:

- Der `:unstable`-Container-Tag erhält kontinuierlich die neuesten Patches (Rolling Tag).
- Bei schwerwiegenden Schwachstellen (CVSS ≥ 9.0) werden auch versionierte Tags mit einem Patch-Release aktualisiert.

**ENISA-Meldung**:

Ein Prozess zur Meldung aktiv ausgenutzter Schwachstellen an die ENISA gemäß Artikel 10(2) CRA wird mit Inkrafttreten der entsprechenden ENISA-Meldeinfrastruktur (voraussichtlich ab 2026) etabliert. Intern ist der Prozess definiert: Sobald eine aktiv ausgenutzte Schwachstelle in DevGuard bekannt wird, erfolgt die Meldung an die zuständige nationale Behörde (BSI) sowie an die ENISA innerhalb von 24 Stunden nach Bekanntwerden.
