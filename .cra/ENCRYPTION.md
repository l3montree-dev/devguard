---
tls:
  minimum_version: "1.2"
  termination: reverse-proxy
password_hashing: argon2
signing:
  algorithm: ECDSA-P256
  public_key: https://raw.githubusercontent.com/l3montree-dev/devguard/main/cosign.pub
intoto_public_key: https://raw.githubusercontent.com/l3montree-dev/devguard/main/intoto-public-key.pem
---

# Encryption

**Datenverschlüsselung In Transit**:

Alle Kommunikationen zwischen Clients und dem DevGuard-Backend erfolgen über HTTPS (TLS 1.2 oder höher). Die TLS-Terminierung findet am vorgelagerten Reverse Proxy/Load Balancer statt (z. B. Nginx, Caddy, oder Cloud-LB). Innerhalb des Service-Netzwerks wird ebenfalls verschlüsselte Kommunikation empfohlen.

- **Ory Kratos**: Alle Authentifizierungs-Flows und Session-Cookies werden ausschließlich über HTTPS übertragen.
- **OAuth2/OIDC-Flows** (GitLab, opencode.de): Kommunikation mit externen Identity-Providern erfolgt ausschließlich über TLS-gesicherte Verbindungen.
- **API-Kommunikation**: Der Echo-HTTP-Server (v4) stellt keine unverschlüsselten HTTP-Endpunkte für Produktivbetrieb bereit.
- **PGP-Verschlüsselung**: Für die Kommunikation im Rahmen des Vulnerability Disclosure Programs wird PGP-Verschlüsselung (ProtonMail gopenpgp v2/v3) eingesetzt.

**Datenverschlüsselung At Rest**:

- **Passwörter**: Passwort-Hashing und -Verwaltung erfolgt ausschließlich über Ory Kratos mit modernen Hashing-Algorithmen (bcrypt/argon2). DevGuard selbst speichert keine Klartextpasswörter.
- **Datenbank**: PostgreSQL-Datenbank; Verschlüsselung at rest wird auf Infrastrukturebene konfiguriert (z. B. verschlüsselte Volumes, Cloud-Provider-Encryption). Es wird empfohlen, AES-256 oder gleichwertige Verschlüsselung auf Volume-/Datenbankebene zu aktivieren.
- **Personal Access Tokens (PAT)**: PATs werden als kryptografische Schlüsselpaare (Public/Private Key) verwaltet. Nur der Public Key wird serverseitig gespeichert. Der Private Key verbleibt beim Nutzer.
- **Signaturen & Attestierungen**: Container-Images und Release-Artefakte werden mit Cosign (ECDSA-P256) signiert. In-toto-Attestierungen sichern die Build-Chain ab.
- **Secrets in CI/CD**: Alle Secrets in der GitHub-Actions-Pipeline werden als verschlüsselte GitHub Secrets gespeichert und nie im Klartext geloggt.
