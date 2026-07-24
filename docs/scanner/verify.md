---
title: DevGuard-Scanner intoto verify — Check supply chain verification status
description: Query the DevGuard supply chain verification endpoint to confirm all required pipeline steps ran correctly, intended for automated deployment gates rather than direct use.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner intoto verify
lang: en-US
ignoreChecks: null
---

## intoto verify

Check with DevGuard whether a supply chain is fully verified (intended for automated deployment gates, not direct use)

### Synopsis

Calls the DevGuard supply chain verification endpoint and exits 0 if the supply chain is valid,
non-zero otherwise.

This command is CURRENTLY (https://github.com/l3montree-dev/devguard/issues/2202) NOT intended to be called by human users. It exists so that automated deployment
gates — such as an OPA policy, an admission webhook, or a CI/CD quality gate — can query DevGuard
for the verification status of a specific image digest before allowing a deployment to proceed.

DevGuard performs the verification server-side: it checks that all three required pipeline steps
(post-commit, build, deploy) have uploaded signed links for the given supply chain ID, that each
step was signed by an authorized token, and that the final deploy link's output digest matches
the --supplyChainOutputDigest you provide.

The underlying endpoint is a plain HTTP GET that returns 200 on success and a non-200 status on
failure — easy to call directly from policy engines or shell scripts:

  GET /api/v1/organizations/<assetName>/in-toto/verify?supplyChainId=<id>&supplyChainOutputDigest=<digest>

```shell
devguard-scanner intoto verify [flags]
```

### Examples

```shell
  # Called by an automated deployment gate (e.g. OPA external data, admission webhook, CI gate)
  devguard-scanner intoto verify \
    --supplyChainOutputDigest sha256:abc123… --token $TOKEN \
    --apiUrl https://api.devguard.org --assetName org/project/app
```

### Options

```shell
  -h, --help                             help for verify
      --supplyChainOutputDigest string   The image supplyChainOutputDigest to verify (e.g. sha256:abc123…)
      --token string                     DevGuard personal access token
```

### Options inherited from parent commands

```shell
      --apiUrl string            The devguard api url
      --assetName string         The asset name to use
      --generateSlsaProvenance   Generate SLSA provenance for the in-toto link. The provenance will be stored in <stepname>.provenance.json. It will be signed using the intoto token.
      --ignore stringArray       The ignore patterns for the in-toto link (default [.git/**/*])
  -l, --logLevel string          Set the log level. Options: debug, info, warn, error (default "info")
      --materials stringArray    The materials to include in the in-toto link. Default is the current directory (default [.])
      --products stringArray     The products to include in the in-toto link. Default is the current directory (default [.])
      --step string              The name of the in-toto link
      --supplyChainId string     The supply chain id to use. If empty, tries to extract the current commit hash.
```
