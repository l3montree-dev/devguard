---
sbom:
  format: cyclonedx-1.4-json
  url: https://api.main.devguard.org/api/v1/organizations/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/artifacts/pkg%3Aoci%2Fdevguard%3Frepository_url%3Dghcr.io%2Fl3montree-dev%2Fdevguard/sbom.json/
  oci_image: ghcr.io/l3montree-dev/devguard:main
vuln_db_sync_interval_hours: 6
ci_pipeline: https://github.com/l3montree-dev/devguard/blob/main/.github/workflows/devguard-scanner.yaml
vuln_db_pipeline: https://github.com/l3montree-dev/devguard/blob/main/.github/workflows/vulndb.yaml
tools:
  - name: trivy
    version: 0.69.2
  - name: gitleaks
    version: 8.30.0
  - name: cosign
    version: 2.6.2
  - name: crane
    version: 0.20.7
---

# Security Scanning

**Dependency Scanning**:

DevGuard setzt eine umfassende, mehrschichtige Sicherheits-Scan-Strategie ein und nutzt dabei die eigene Plattform zur Selbstüberprüfung (Dogfooding).

**Automatisierte Scans in CI/CD** (`.github/workflows/devguard-scanner.yaml`):

| Scan-Typ                     | Tool                        | Frequenz              |
|------------------------------|-----------------------------|-----------------------|
| Software Composition Analysis (SCA) | DevGuard + Trivy v0.69.2 | Jeder Push / PR      |
| Container Image Scanning     | Trivy v0.69.2               | Jeder Push / PR       |
| SBOM-Generierung             | DevGuard Scanner + Trivy    | Jeder Push / PR       |
| Secret Scanning              | Gitleaks v8.30.0            | Jeder Push / PR       |
| Static Analysis (SAST)       | golangci-lint, DevGuard     | Jeder Push / PR       |
| Vulnerability Database Sync  | DevGuard vulndb             | Alle 6 Stunden        |
| Supply Chain Attestierung    | Cosign + In-toto (SLSA L3)  | Jeder Release         |

**Verwendete Tools**:
- **DevGuard Action** (`devguard-action`): Eigene GitHub Action für SCA, Container-Scanning und SBOM-Attestierung
- **Trivy** (v0.69.2): Container-Image- und Dependency-Scanning; SHA256-verifiziert installiert
- **Gitleaks** (v8.30.0): Secret-Detection in Quellcode und Git-History; SHA256-verifiziert
- **golangci-lint**: Statische Code-Analyse mit sicherheitsrelevanten Regeln (`gosec`, etc.)
- **Cosign** (v2.6.2): Signierung und Verifizierung von Images und Attestierungen
- **Crane** (v0.20.7): Container-Registry-Interaktionen

**Vulnerability-Datenbank**:
DevGuard synchronisiert seine eigene Vulnerability-Datenbank alle 6 Stunden aus folgenden Quellen:
- OSV (Open Source Vulnerabilities)
- CISA KEV (Known Exploited Vulnerabilities)
- EPSS (Exploit Prediction Scoring System)
- ExploitDB
- GitHub Advisory Database
- Debian Security Tracker
- MITRE CVE / CVSS-Daten
- Malicious Packages Checker

**Exploitability Assessment**:
Erkannte Schwachstellen werden nicht nur nach CVSS-Score, sondern auch nach Ausnutzbarkeit (EPSS, CISA KEV, ExploitDB-Daten) priorisiert. Der resultierende Risk-Score (0–10) kombiniert Base Score, EPSS, Threat Intelligence und Abhängigkeitstiefen.

**Ergebnisbehandlung**:
- Erkannte Schwachstellen werden automatisch in DevGuard erfasst und priorisiert
- Kritische und ausnutzbare Schwachstellen blockieren den Release-Prozess
- Falsch-Positive können mit Begründung als „akzeptiert" markiert werden (auditierbar)
