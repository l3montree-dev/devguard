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

Inspect and correlate log files from any devguard component. The format is
detected per file:

| Format | Produced by | Notes |
|---|---|---|
| `api` | devguard-api, scanner (zerolog console writer) | wall clock only — **no date, no timezone** |
| `kratos` | Ory Kratos (logfmt) | absolute timestamps |
| `postgres` | PostgreSQL server log | absolute timestamps; `DETAIL`/`HINT`/`STATEMENT`/`CONTEXT` are folded into the entry they annotate |
| `web` | devguard-web (Next.js server output) | **no timestamps**; stack frames folded into the error, grouped by Next.js `digest` |

Levels are normalised to `DBG`/`INF`/`WRN`/`ERR`/`FTL` across every format, so
`--level`, `errors` and `timeline` behave the same whichever log you point them
at. Override detection with `--format/-F`, and check what a file looks like with
`logs formats`.

Any log collected with `kubectl logs --timestamps` is also understood — the
RFC3339 prefix is stripped and used as the entry's timestamp. That is the only
way to put the Next.js web log on a timeline.

Log content is printed in full: nothing is truncated by width, and the
continuation lines of a multi-line entry are printed indented under it. Lines
matching neither a format's parse nor its continuation rules are counted and
reported on stderr rather than silently dropped.

```bash
devguard-maint logs -f api.log summary        # levels, top sources, top messages
devguard-maint logs -f api.log errors         # every ERR and FTL entry
devguard-maint logs -f api.log filter -l ERR -c auswaertiges-amt
devguard-maint logs -f postgres.log timeline  # per-minute level histogram
devguard-maint logs -f web.log formats        # what did it detect, and why
```

#### Counting a kind of failure

`summary` groups on the exact message, so events carrying a request id, address
or duration each land in their own bucket. `--normalize/-N` replaces those tokens
with placeholders first, which collapses one kind of failure into one row.
Combine it with `--top/-t` to reach past the default 15:

```bash
devguard-maint logs -f api.log summary -N --top 200 | grep "connection refused"
```

```
    12  could not get session from cookie error="... dial tcp <addr>: connect: connection refused"
    12  critical error encountered msg="kratos: could not get identity from cookie" error="... <addr> ..."
     2  failed to get identity err="... /admin/identities/<uuid> ... <addr> ..."
```

Tokens replaced: `<ts>`, `<date>`, `<uuid>`, `<addr>` (IP, optionally with port),
`<hex>` (16+ hex chars), `<dur>`, `<n>`. For a plain occurrence count of one
substring, `filter -c "connection refused"` reports the number of matches.

#### `logs correlate <file> <file> [file...]`

Lines several logs up on one timeline so an error in one component can be read
against what every other component was doing at that instant. The matrix shows
`total/errors` per bucket, and `!` marks any bucket containing an `ERR` or `FTL`.

```bash
devguard-maint logs correlate api.log kratos.log postgres.log --only-errors
```

```
  BUCKET           api        kratos     postgres
! 2026-08-11 14:09 31/4       72         16
! 2026-08-11 14:11 431/25     121        50
! 2026-08-11 14:12 142/2      290        92
```

Then drop into the actual interleaved lines around a moment of interest:

```bash
devguard-maint logs correlate api.log kratos.log --around 14:11 --window 30s
```

**Timestamps differ per component, and this is the main source of wrong
conclusions.** Postgres and Kratos log absolute dates in UTC. The api log prints
a wall clock with no date and no timezone; it is anchored so its last entry lands
on the last date seen in the dated logs, and is *assumed to share their zone* —
the header states when a date was inferred. Its stamps have minute resolution, so
api entries land at second `:00` relative to postgres and kratos. If a log really
is in another zone, shift it:

```bash
devguard-maint logs correlate api.log kratos.log --offset api=+2h
```

A log with no timestamps at all cannot be aligned; it is reported separately with
its errors listed, not folded silently into the matrix.

Other flags: `--bucket second|minute|hour`, `--level`, and `--date YYYY-MM-DD` to
anchor undated logs explicitly.

## Typical release order

1. Update all CHANGELOGs with the new version entry
2. `release devguard <tag>` — backend
3. `release web <tag>` — frontend (can be skipped for backend-only patches)
4. `release helm-chart <tag>` — Helm chart (auto-detects latest backend/web tags)
5. `release ci-components <tag>` — CI templates (auto-detects latest scanner tag)
