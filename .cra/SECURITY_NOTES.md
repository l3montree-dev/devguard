---
readme: https://github.com/l3montree-dev/devguard/blob/main/README.md
security_policy: https://github.com/l3montree-dev/devguard/blob/main/SECURITY.md
releases: https://github.com/l3montree-dev/devguard/releases
security_advisories: https://github.com/l3montree-dev/devguard/security/advisories
openapi_spec: https://api.main.devguard.org/swagger/index.html
container_image: ghcr.io/l3montree-dev/devguard
cosign_public_key: https://raw.githubusercontent.com/l3montree-dev/devguard/main/cosign.pub
mfa_supported: true
---

# Security Notes / Dokumentation und Nutzertransparenz

**Nutzerdokumentation**:

DevGuard stellt umfassende Nutzerdokumentation bereit, die informierte Entscheidungen gemäß Artikel 10(3) CRA ermöglicht:

- **README.md**: Installations- und Konfigurationsanleitung inkl. Docker-Compose-Setup, Umgebungsvariablen und Sicherheitshinweise
- **OpenAPI/Swagger-Dokumentation**: Maschinenlesbare API-Spezifikation für alle REST-Endpunkte (automatisch generiert)
- **SECURITY.md**: Sicherheitsrichtlinie mit Versionsübersicht, VDP-Anweisungen und PGP-Kontakt
- **Changelogs / GitHub Releases**: Transparente Kommunikation aller Änderungen inkl. Security-Fixes mit CVE-Referenzen

**Sicherheitshinweise für Endnutzer**:

- **Versionsmanagement**: Der `:unstable`-Tag erhält kontinuierlich die neuesten Patches. Für Produktion werden versionierte Tags empfohlen. Bei schwerwiegenden Schwachstellen (CVSS ≥ 9.0) werden auch ältere Tags aktualisiert.
- **2FA / MFA**: Nutzer werden empfohlen, Multi-Faktor-Authentifizierung über den konfigurierten Identity Provider (Ory Kratos / OAuth2) zu aktivieren.
- **Personal Access Tokens**: PATs sollten mit minimalen Berechtigungen erstellt und regelmäßig rotiert werden. Private Keys verbleiben ausschließlich beim Nutzer und werden nicht serverseitig gespeichert.
- **TLS-Konfiguration**: Für Produktiv-Deployments ist die Konfiguration eines vorgelagerten Reverse Proxys mit TLS 1.2+ erforderlich. Self-signed Certificates sollten nur in Entwicklungsumgebungen verwendet werden.
- **Image-Verifikation**: Vor dem Deployment sollte die Cosign-Signatur des Container-Images verifiziert werden: `cosign verify --key cosign.pub ghcr.io/l3montree-dev/devguard:latest`

**Update-Benachrichtigungen**:

- GitHub Release Notifications via Repository Watch / Subscribe
- SBOM-Vergleich zwischen Releases ermöglicht automatisierte Erkennung neuer Abhängigkeiten
- Sicherheits-Advisory über GitHub Security Advisories (öffentlich nach Fix)
