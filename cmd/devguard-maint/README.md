# devguard-maint

Maintenance CLI for DevGuard. Handles release management, log inspection, and scanner documentation generation.

## Installation

```bash
go install github.com/l3montree-dev/devguard/cmd/devguard-maint@latest
```

Or build from source inside the `devguard` repo:

```bash
go build -o devguard-maint ./cmd/devguard-maint && mv devguard-maint $(go env GOPATH)/bin
```

## Directory layout requirement

All release commands work with **sibling directories**. Before running any `release` subcommand, navigate to the **parent directory** that contains all DevGuard repositories side by side:

```
~/workspace/
├── devguard/               ← main backend repo (also where you build this tool)
├── devguard-web/           ← frontend repo
├── devguard-helm-chart/    ← Helm chart repo
├── devguard-ci-component/  ← CI component repo
└── devguard-documentation/ ← public documentation repo
```

```bash
cd ~/workspace   # <-- run devguard-maint from here, NOT from inside a repo
devguard-maint release devguard v1.8.0
```

The directory names must match exactly:

| Expected name | Repo |
|---|---|
| `devguard` | `github.com/l3montree-dev/devguard` |
| `devguard-web` | `github.com/l3montree-dev/devguard-web` |
| `devguard-helm-chart` | `github.com/l3montree-dev/devguard-helm-chart` |
| `devguard-ci-component` | `github.com/l3montree-dev/devguard-ci-component` |
| `devguard-documentation` | `github.com/l3montree-dev/devguard-documentation` |

## Commands

### `release devguard <tag>`

Tags and pushes the **devguard backend** only. Fails if `devguard/CHANGELOG.md` has no entry for `<tag>`.

Before tagging, it also runs `make docs` inside `devguard`, failing if that command errors. If it produces changes under `devguard/docs`, those are automatically committed (`docs: regenerate for <tag>`) and pushed. It then copies the generated `devguard/docs/scanner/*.md` files into `devguard-documentation/src/pages/reference/scanner/`, and if that produces changes, commits (`docs: regenerate scanner reference for <tag>`) and pushes them in the `devguard-documentation` repo too.

Requires a `devguard-documentation` sibling directory (see layout above).

```bash
devguard-maint release devguard v1.8.0
```

### `release web <tag>`

Bumps `package.json`, commits, tags, and pushes **devguard-web** only. Fails if `devguard-web/CHANGELOG.md` has no entry for `<tag>`.

```bash
devguard-maint release web v1.8.0
```

### `release helm-chart <tag>`

Updates `Chart.yaml`, `values.yaml`, and `docker-compose-try-it.yaml` with the latest detected `devguard` and `devguard-web` patch tags for the same minor version, then commits, pushes, and tags `devguard-helm-chart`. Fails if:
- `devguard-helm-chart/CHANGELOG.md` has no entry for `<tag>`
- No `devguard` or `devguard-web` release exists with the same minor version

```bash
devguard-maint release helm-chart v1.8.1
```

### `release ci-components <tag>`

Pins the devguard scanner image in `src/container-image-versions.ts`, runs `bun run generate` to regenerate all templates, tags `devguard-ci-component`, then reverts and regenerates again so `main` always uses `scanner:main`. Fails if:
- `devguard-ci-component/CHANGELOG.md` has no entry for `<tag>`
- No `devguard` release exists with the same minor version

Requires `bun` to be installed.

```bash
devguard-maint release ci-components v1.8.0
```

### `docs [output-dir]`

Generates markdown documentation for `devguard-scanner` into `output-dir` (default: `docs/scanner`).

```bash
devguard-maint docs
devguard-maint docs /tmp/scanner-docs
```

### `logs`

Inspect devguard log files.

```bash
devguard-maint logs --help
```

## Typical release order

1. Update all CHANGELOGs with the new version entry
2. `release devguard <tag>` — backend
3. `release web <tag>` — frontend (can be skipped for backend-only patches)
4. `release helm-chart <tag>` — Helm chart (auto-detects latest backend/web tags)
5. `release ci-components <tag>` — CI templates (auto-detects latest scanner tag)
