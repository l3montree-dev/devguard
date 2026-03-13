---
sbom:
  format: cyclonedx-1.4-json
  url: https://api.main.devguard.org/api/v1/organizations/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/artifacts/pkg%3Aoci%2Fdevguard%3Frepository_url%3Dghcr.io%2Fl3montree-dev%2Fdevguard/sbom.json/
  oci_image: ghcr.io/l3montree-dev/devguard:main
  update_trigger: per-release
slsa:
  level: 3
cosign_public_key: https://raw.githubusercontent.com/l3montree-dev/devguard/main/cosign.pub
---

# Software Bill of Materials (SBOM)

**SBOM-Format**:

CycloneDX (primär) und SPDX werden unterstützt. Die generierten SBOMs liegen im JSON-Format vor und sind maschinenlesbar gemäß den Anforderungen des CRA (Anhang I, Teil III). DevGuard verarbeitet intern CycloneDX-1.4-konforme SBOMs und unterstützt deren Erstellung und Analyse als Kernfunktion der Plattform.

**Aktualisierungszyklus**:

SBOMs werden bei jedem Release automatisch generiert und aktualisiert. Bei kritischen Sicherheitspatches erfolgt eine außerplanmäßige Aktualisierung. Die Generierung ist vollständig in die CI/CD-Pipeline integriert (`.github/workflows/devguard-scanner.yaml`).

**Tools zur Generierung**:

- **Trivy** (v0.69.2): Primäres Tool zur SBOM-Generierung für Container-Images und Go-Abhängigkeiten
- **DevGuard Scanner** (`cmd/devguard-scanner`): Eigenes CLI-Tool zur SBOM-Erstellung, -Verarbeitung und -Attestierung
- **Cosign** (v2.6.2): Signierung der SBOMs als Supply-Chain-Attestierungen
- **In-toto**: Supply-Chain-Metadaten und Attestierungen für die Build-Pipeline

Die Integrität aller verwendeten Tools wird über SHA256-Prüfsummen in der Build-Pipeline verifiziert (`Dockerfile.scanner`).

**Veröffentlichung**:

SBOMs sind öffentlich über die DevGuard API verfügbar:

- DevGuard (Backend): `https://api.main.devguard.org/api/v1/organizations/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/artifacts/pkg%3Aoci%2Fdevguard%3Frepository_url%3Dghcr.io%2Fl3montree-dev%2Fdevguard/sbom.json/`
- Interne Ablage: Im GitHub Container Registry (GHCR) als OCI-Artefakt, signiert mit Cosign
- Für Kunden und Behörden auf Anfrage verfügbar
- Archivierung im openCode-Repository geplant

Container-Images werden mit SLSA Level 3 Provenance veröffentlicht und sind über Cosign verifizierbar (`cosign.pub` im Repository).
