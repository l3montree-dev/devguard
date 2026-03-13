---
standards:
  - OWASP-Top-10
  - CERT-Go
  - CWE-SANS-Top-25
sast_tools:
  - golangci-lint
  - semgrep
  - gitleaks
openssf_badge: https://www.bestpractices.dev/projects/8928
goreportcard: https://goreportcard.com/report/github.com/l3montree-dev/devguard
ci_pipeline: https://github.com/l3montree-dev/devguard/blob/main/.github/workflows/devguard-scanner.yaml
---

# Secure Coding Standard

**Einhaltung Secure Coding Standards**:

DevGuard folgt etablierten Secure-Coding-Standards und integriert diese in den gesamten Entwicklungsprozess:

**Standards**:
- **OWASP Top 10**: Alle bekannten OWASP-Top-10-Risiken werden im Code-Review-Prozess und durch automatisierte Tools adressiert (Injection, XSS, IDOR, SSRF, etc.)
- **CERT Go / CERT C**: Sichere Programmierpraktiken für Go (Speicherverwaltung, Nebenläufigkeit, Fehlerbehandlung)
- **CWE/SANS Top 25**: Berücksichtigung der häufigsten Software-Schwachstellen in Design und Review

**Tools zur statischen Code-Analyse (SAST)**:
- **golangci-lint** (30 Minuten Timeout-Konfiguration): Umfassende Lint-Prüfungen inkl. sicherheitsrelevanter Regeln (z. B. `gosec`, `staticcheck`, `errcheck`). Läuft in der CI/CD-Pipeline (`.github/workflows/devguard-scanner.yaml`)
- **DevGuard SAST-Scanner**: SAST-Integration via `devguard-action` für automatisierte Schwachstellenerkennung im Quellcode
- **Semgrep** (über DevGuard Scanner): Pattern-basierte statische Analyse für bekannte Schwachstellenmuster
- **Gitleaks** (v8.30.0): Erkennung versehentlich eingebetteter Secrets und Credentials im Quellcode und der Git-History

**Code-Review-Prozess**:
- Alle Änderungen durchlaufen einen Pull-Request-Review vor dem Merge
- Security-relevante Änderungen (Authentifizierung, RBAC, Kryptografie) erfordern explizite Überprüfung
- Automatisierte CI/CD-Checks müssen vor dem Merge erfolgreich sein

**Dependency Management**:
- Go-Abhängigkeiten werden mit `go.sum` verifiziert (kryptografische Checksummen)
- Regelmäßige Dependency-Updates über GitHub Dependabot und DevGuard-Self-Scanning
- Minimierung externer Abhängigkeiten nach dem Prinzip der geringsten Abhängigkeit

**OpenSSF Best Practices**:
- DevGuard ist OpenSSF Best Practices Badge zertifiziert: https://www.bestpractices.dev/projects/8928
- Code-Qualitätsüberwachung via GoReportCard
