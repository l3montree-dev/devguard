<!--
<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->

<!-- PROJECT LOGO -->
<br />
<div align="center">

  <picture>
    <source srcset="images/logo_inverse_horizontal.svg"  media="(prefers-color-scheme: dark)">
    <img src="images/logo_horizontal.svg" alt="DevGuard by L3montree Logo" width="240" height="80">
  </picture>

  <h3 align="center">DevGuard - Develop Secure Software - Backend</h3>

  <p align="center">
    Manage your CVEs seamlessly, Integrate your Vulnerability Scanners, Documentation made easy, Compliance to security Frameworks
    <br />
    <br />
    <a href="https://github.com/l3montree-dev/devguard/issues">Report Bug</a>
    ·
    <a href="https://github.com/l3montree-dev/devguard/issues">Request Feature</a>
    ·
    <a href="https://github.com/l3montree-dev/devguard?tab=readme-ov-file#sponsors-and-supporters-">Sponsors</a>
  </p>
</div>

<p align="center">
   <a href="https://www.bestpractices.dev/projects/8928"><img src="https://www.bestpractices.dev/projects/8928/badge" alt="OpenSSF Badge"></a>
   <a href="https://github.com/l3montree-dev/devguard/blob/main/LICENSE.txt"><img src="https://img.shields.io/badge/license-AGPLv3-purple" alt="License"></a>
   <a href="https://github.com/l3montree-dev/devguard/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22"><img src="https://img.shields.io/badge/Help%20Wanted-Contribute-blue"></a>
   <a href="https://matrix.to/#/#devguard:matrix.org"><img src="https://img.shields.io/matrix/devguard%3Amatrix.org?logo=matrix&label=matrix"></a>
   <a href="https://main.devguard.org/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main"><img src="https://api.main.devguard.org/api/v1/badges/cvss/7d404549-3a17-47d8-b732-b26e6a4eeb00" alt="CVSS"></a>
</p>

<p align="center">
Get in touch with the developers directly via 
  <a href="https://matrix.to/#/#devguard:matrix.org">Matrix-Chat</a>
</p>
Visit the Documentation at: https://devguard.org

<!-- ABOUT THE PROJECT -->
## Mission

DevGuard is built by developers, for developers, aiming to simplify the complex world of vulnerability management. Our goal is to integrate security seamlessly into the software development lifecycle, ensuring that security practices are accessible and efficient for everyone, regardless of their security expertise.

### Demo

We are using DevGuard to scan and manage the risks of DevGuard itself—essentially eating our own dogfood. The project can be found here:

[DEMO](https://main.devguard.org/l3montree-cybersecurity/projects/devguard)

We believe VEX information should be shared via a link due to its dynamic nature, as what is risk-free today may be affected by a CVE tomorrow. We've integrated the DevGuard risk scoring into the metrics, with detailed documentation on its calculation to follow soon. SBOM and VEX data are always up to date at these links: 

|Project|SBOM|VeX|
|---|---|---|
|[Devguard Golang API](https://github.com/l3montree-dev/devguard)|[SBOM](https://main.devguard.org/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/sbom.json?scanner=github.com%2Fl3montree-dev%2Fdevguard%2Fcmd%2Fdevguard-scanner%2Fcontainer-scanning)|[VeX](https://main.devguard.org/l3montree-cybersecurity/projects/devguard/assets/devguard/refs/main/vex.json?scanner=github.com%2Fl3montree-dev%2Fdevguard%2Fcmd%2Fdevguard-scanner%2Fcontainer-scanning)|
|[Devguard Web-Frontend](https://github.com/l3montree-dev/devguard-web)|[SBOM](https://main.devguard.org/l3montree-cybersecurity/projects/devguard/assets/devguard-web/refs/main/sbom.json?scanner=github.com%2Fl3montree-dev%2Fdevguard%2Fcmd%2Fdevguard-scanner%2Fcontainer-scanning)|[VeX](https://main.devguard.org/l3montree-cybersecurity/projects/devguard/assets/devguard-web/refs/main/vex.json?scanner=github.com%2Fl3montree-dev%2Fdevguard%2Fcmd%2Fdevguard-scanner%2Fcontainer-scanning)|

### The problem we solve

Identifying and managing software vulnerabilities is an increasingly critical challenge. Developers often face security issues without the proper training or tools that fit into their everyday workflows. DevGuard is a developer-centered software designed to provide simple, modern solutions for vulnerability detection and management, compliant with common security frameworks.

In 2023 alone, cyberattacks caused approximately 206 billion euros in damage only in Germany. Many of these attacks exploited software vulnerabilities. With agile and DevOps methodologies becoming standard, the need for integrating security into the development process has never been greater. We aim to fill this gap with DevGuard, offering a seamless integration of vulnerability management into development workflows.


### DevGuard Features

DevGuard comes with a lot of features to make safe Software Development as easy as possible for you. Here are some impressions of feature you will experience while using DevGuard:

#### Auto-Setup

We developed an auto setup functionality to speed up the DevGuard integration process.

<img width="3000" height="1680" alt="auto-setup" src="https://github.com/user-attachments/assets/ec7817ce-92cb-4cfc-a019-0129ffc6dcbf" />


#### Enhanced Risk Calculation

When it comes to your actual vulnerability risk, the CVSS score is not enough. To help you prioritise based on the actual risk to your project, we enhance the CVSS score with information about exploitability and calculate the risk score based on your confidentiality, integrity and availability assessment. This ensures that the most important things come first!

<img width="1706" height="973" alt="management" src="https://github.com/user-attachments/assets/1774eef0-2122-4601-a379-9b1c7b49394a" />



#### Dependency overview

Security through obscurity may have worked in the past, but we want to develop software using modern methods! The obscurity shouldn't affect you either. That's why we developed DevGuard: to give you full transparency over your dependencies and highlight any vulnerabilities. This is also visible in a fancy dependency graph.

<img width="1702" height="688" alt="deps" src="https://github.com/user-attachments/assets/3dce3e70-3e5b-49c0-8d99-803f7c95d9a2" />


<!-- INSTALLATION -->
## Scanner Installation

DevGuard Scanner can be installed in multiple ways. Choose the method that best fits your environment:

### Go Install (Recommended)

The easiest way to install the latest version:

```bash
# Install the latest version
go install github.com/l3montree-dev/devguard/cmd/devguard-scanner@latest

# Install a specific version
go install github.com/l3montree-dev/devguard/cmd/devguard-scanner@v1.0.0
```

### Pre-built Binaries

Download pre-built binaries from our [releases page](https://github.com/l3montree-dev/devguard/releases):

```bash
# Download and verify (example for Linux AMD64)
curl -L https://github.com/l3montree-dev/devguard/releases/download/v1.0.0/devguard-scanner_1.0.0_Linux_x86_64.tar.gz -o devguard-scanner.tar.gz

# Verify the download (optional but recommended)
curl -L https://github.com/l3montree-dev/devguard/releases/download/v1.0.0/checksums.txt -o checksums.txt
sha256sum --check --ignore-missing checksums.txt

# Extract and install
tar -xzf devguard-scanner.tar.gz
sudo mv devguard-scanner /usr/local/bin/
```

### Docker

```bash
# Run directly from Docker Hub
docker run --rm -v $(pwd):/app ghcr.io/l3montree-dev/devguard-scanner:latest sca /app

# Pull the image first
docker pull ghcr.io/l3montree-dev/devguard-scanner:latest
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/l3montree-dev/devguard.git
cd devguard

# Build the scanner
make devguard-scanner

# Or build with release flags for production
make release-devguard-scanner
```

### Security Verification

All our releases are cryptographically signed and include SLSA Level 3 provenance for supply chain security.

**Verify binary signatures:**
```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Verify the checksums file signature
cosign verify-blob \
  --certificate-identity-regexp="^https://github.com/l3montree-dev/devguard/.github/workflows/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --bundle checksums.txt.sig.bundle \
  checksums.txt
```

**Verify container images:**
```bash
cosign verify ghcr.io/l3montree-dev/devguard-scanner:latest \
  --certificate-identity-regexp="^https://github.com/l3montree-dev/devguard/.github/workflows/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### ✅ Verify Installation

```bash
# Check if installation was successful
devguard-scanner --version

# Get help
devguard-scanner --help

# Run a quick security scan
devguard-scanner sca --help
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTRIBUTING -->
## Contributing

We welcome contributions! Please read our [contribution guide](./CONTRIBUTING.md) if you would like to report a bug, ask a question, write issues, or help us with coding. All help is appreciated!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- Code of Conduct -->
## Code of Conduct

Help us keep DevGuard open and inclusive. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Built With

DevGuard is divided into two projects: A frontend (DevGuard Web) and a backend (DevGuard Backend). 

**Backend (this project):**
* [![Go][go.dev]][go-url]

**Frontend:**
* Please refer to: [DevGuard-Web on Github](https://github.com/l3montree-dev/devguard-web)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Database Migrations

DevGuard uses [golang-migrate](https://github.com/golang-migrate/migrate) for database schema management. All migrations are embedded in the binary and run automatically on startup.

### How Database Migrations Work

1. **Automatic Migration**: By default, migrations run automatically when the application starts
2. **Environment Control**: Set `DISABLE_AUTOMIGRATE=true` to disable automatic migrations
3. **Embedded Migrations**: Migration files are embedded in the binary for easy deployment
4. **Idempotent**: Migrations can be run multiple times safely

### Creating New Migrations

#### 1. Install the Migration Tool

The project includes golang-migrate as a tool dependency. Install it using:

```bash
go get -tool github.com/golang-migrate/migrate/v4/cmd/migrate
```

#### 2. Create a New Migration

```bash
# Create a new migration file pair (.up.sql and .down.sql)
go tool migrate create -ext sql -dir internal/database/migrations your_migration_name

# Example: Adding a new table
go tool migrate create -ext sql -dir internal/database/migrations add_user_preferences_table
```

This creates two files:
- `internal/database/migrations/YYYYMMDDHHMMSS_your_migration_name.up.sql` - Forward migration
- `internal/database/migrations/YYYYMMDDHHMMSS_your_migration_name.down.sql` - Rollback migration

#### 3. Write Your Migration

**Example: Adding a new table**

`20250801120000_add_user_preferences_table.up.sql`:
```sql
-- Create user preferences table
CREATE TABLE IF NOT EXISTS user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    theme TEXT DEFAULT 'light',
    notifications_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON user_preferences(user_id);
```

`20250801120000_add_user_preferences_table.down.sql`:
```sql
-- Remove the user preferences table
DROP TABLE IF EXISTS user_preferences CASCADE;
```

**Example: Adding a column**

`20250801130000_add_email_to_users.up.sql`:
```sql
-- Add email column to existing users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;

-- Add index for email lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
```

`20250801130000_add_email_to_users.down.sql`:
```sql
-- Remove email column from users table
ALTER TABLE users DROP COLUMN IF EXISTS email CASCADE;
```

**Example: Adding foreign key constraints**

`20250801140000_add_user_organization_fk.up.sql`:
```sql
-- Add foreign key constraint
ALTER TABLE users 
ADD CONSTRAINT IF NOT EXISTS fk_users_organization 
FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE;
```

`20250801140000_add_user_organization_fk.down.sql`:
```sql
-- Remove foreign key constraint
ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_organization;
```

#### 4. Best Practices

- **Always use IF NOT EXISTS/IF EXISTS**: Makes migrations idempotent
- **Include rollback logic**: Always write the down migration
- **Test migrations**: Test both up and down migrations on a copy of production data
- **Small incremental changes**: Keep migrations focused and atomic
- **Use transactions implicitly**: PostgreSQL wraps DDL in transactions automatically
- **Descriptive names**: Use clear, descriptive migration names

#### 5. Manual Migration Commands

```bash
# Check migration status
go tool migrate -database "postgres://user:pass@localhost:5432/devguard?sslmode=disable" -path internal/database/migrations version

# Run migrations manually
go tool migrate -database "postgres://user:pass@localhost:5432/devguard?sslmode=disable" -path internal/database/migrations up

# Rollback one migration
go tool migrate -database "postgres://user:pass@localhost:5432/devguard?sslmode=disable" -path internal/database/migrations down 1

# Rollback to specific version
go tool migrate -database "postgres://user:pass@localhost:5432/devguard?sslmode=disable" -path internal/database/migrations goto 20250801120000
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the AGPL-3.0-or-later License. See [`LICENSE.txt`](LICENSE.txt) for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Sponsors and Supporters 🚀

We are proud to be supported and working together with the following organizations:

[![OWASP](./images/sponsors/sp-owasp.png)](https://owasp.org/)
[![Bonn-Rhein-Sieg University of Applied Science](./images/sponsors/sp-hbrs.png)](https://www.h-brs.de/)
[![WhereGroup](./images/sponsors/sp-wheregroup.png)](https://wheregroup.com/)
[![DigitalHub](./images/sponsors/sp-digitalhub.png)](https://www.digitalhub.de/)
[![WetterOnline](./images/sponsors/sp-wetteronline.png)](https://wetteronline.de/)
[![Ikor](./images/sponsors/sp-ikor.png)](https://ikor.one/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[go.dev]: https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white
[go-url]: https://go.dev


### DEVGUARD-SCANNER

#### Build the scanner
```bash
docker build . -f Dockerfile.scanner -t devguard-scanner  
```

#### Use the scanner for sca

```bash
docker run -v "$(PWD):/app" scanner devguard-scanner sca \
  --assetName="<ASSET NAME>" \
  --apiUrl="http://host.docker.internal:8080" \
  --token="<TOKEN>" \
  --path="/app"
```

#### Using the scanner during development

```bash
go run ./cmd/devguard-scanner/main.go sca \
  --assetName="<ASSET NAME>" \
  --apiUrl="http://localhost:8080" \
  --token="<TOKEN>"
```


#### Scan a container

##### Build a image.tar from a dockerfile using kaniko

```bash
docker run --rm -v $(pwd):/workspace gcr.io/kaniko-project/executor:latest --dockerfile=/workspace/Dockerfile --context=/workspace --tarPath=/workspace/image.tar --no-push
```

##### Scan the .tar
```bash
docker run -v "$(PWD):/app" scanner devguard-scanner container-scanning \
  --assetName="<ASSET NAME>" \
  --apiUrl="http://host.docker.internal:8080" \
  --token="<TOKEN>" \
  --path="/app/image.tar"
```

