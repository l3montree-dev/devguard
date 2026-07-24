---
title: DevGuard-Scanner sarif2markdown — Convert SARIF to markdown
description: Convert a SARIF JSON file into a human-readable markdown report with devguard-scanner sarif2markdown for pull requests, wikis, or code review comments.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner sarif2markdown
lang: en-US
ignoreChecks: null
---

## sarif2markdown

Convert a SARIF JSON file into a markdown report

### Synopsis

Convert a SARIF JSON file into a human-readable markdown report.

SARIF is a machine-readable format. This command turns it into markdown so you can paste the
results into a pull request description, a wiki page, or a GitHub/GitLab comment. This is
particularly useful for Kyverno or IaC scan results where you want a readable summary for
reviewers who do not have access to the DevGuard UI.

Two output modes are available:
  - Summary (default): one row per policy rule with pass/fail/skip counts
  - Detailed (--detailed): one row per affected resource, grouped by severity

```shell
devguard-scanner sarif2markdown [flags]
```

### Examples

```shell
  # Convert SARIF to markdown summary
  devguard-scanner sarif2markdown -i results.sarif.json

  # Generate detailed markdown report
  devguard-scanner sarif2markdown -i results.sarif.json --detailed

  # Save to file
  devguard-scanner sarif2markdown -i results.sarif.json -o report.md
```

### Options

```shell
      --detailed        Show detailed results per resource
  -h, --help            help for sarif2markdown
  -i, --input string    Input SARIF JSON file
  -o, --output string   Output markdown file (default: stdout)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
