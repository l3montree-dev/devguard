---
dockerfile: https://github.com/l3montree-dev/devguard/blob/main/Dockerfile
kratos_config: https://github.com/l3montree-dev/devguard/blob/main/.kratos/kratos.yml
rbac_model: https://github.com/l3montree-dev/devguard/blob/main/config/rbac_model.conf
default_passwords: false
anonymous_access: false
container_user: 53111
container_runs_as_root: false
---

# Default Configuration

**Sichere Voreinstellungen / Secure by Default**:

DevGuard ist nach dem Prinzip „Secure by Default" konzipiert. Folgende Sicherheitsvoreinstellungen sind standardmäßig aktiv:

**Authentifizierung & Autorisierung**:
- Alle API-Endpunkte erfordern eine Authentifizierung (Session-basiert via Ory Kratos, Personal Access Token oder Admin Token). Anonymer Zugriff ist nur für explizit öffentlich freigegebene Ressourcen möglich.
- Rollenbasierte Zugriffskontrolle (RBAC) via Casbin ist standardmäßig aktiv. Neue Nutzer erhalten keine Berechtigungen ohne explizite Zuweisung.
- Es existieren keine Standard-Passwörter. Passwörter und Credentials werden ausschließlich über Ory Kratos verwaltet.

**Netzwerk & Transport**:
- HTTPS (TLS) ist für alle Client-Server-Kommunikationen vorgesehen. Die Anwendung stellt selbst kein HTTP-Fallback bereit; TLS-Terminierung erfolgt über den vorgelagerten Reverse Proxy oder Load Balancer.
- HTTP Strict Transport Security (HSTS) wird über den vorgelagerten Proxy konfiguriert.

**Container-Sicherheit**:
- Der Container läuft standardmäßig als nicht privilegierter Benutzer (UID 53111, kein Root).
- Minimales Base-Image (`static` von registry.opencode.de) ohne Shell oder unnötige System-Utilities.
- Multi-Stage-Build zur Reduzierung der Angriffsfläche.
- Alle Build-Abhängigkeiten und externen Tools (Trivy, Crane, Cosign, Gitleaks) werden mit SHA256-Prüfsummen verifiziert.

**OAuth2 / OIDC**:
- OAuth2/OIDC-Integration (GitLab, opencode.de) ist mit State-Parameter und PKCE konfiguriert.
- Tokens werden nicht im Klartext persistiert.

**API-Sicherheit**:
- HTTP-Request-Signing für Personal Access Tokens (PAT) über `X-Signature`- und `X-Fingerprint`-Header.
- Rate-Limiting und Input-Validierung sind auf Middleware-Ebene implementiert.
