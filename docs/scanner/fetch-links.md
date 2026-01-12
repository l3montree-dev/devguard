## intoto fetch-links

Fetch links for a given supply chain

```shell
devguard-scanner intoto fetch-links [flags]
```

### Options

```shell
      --apiUrl string          The devguard api url (default "api.devguard.org")
      --assetName string       The asset name to use
  -h, --help                   help for fetch-links
      --supplyChainId string   The supply chain id to fetch the links for
      --token string           The token to use to authenticate with the devguard api
```

### Options inherited from parent commands

```shell
      --generateSlsaProvenance   Generate SLSA provenance for the in-toto link. The provenance will be stored in <stepname>.provenance.json. It will be signed using the intoto token.
      --ignore stringArray       The ignore patterns for the in-toto link (default [.git/**/*])
  -l, --logLevel string          Set the log level. Options: debug, info, warn, error (default "info")
      --materials stringArray    The materials to include in the in-toto link. Default is the current directory (default [.])
      --products stringArray     The products to include in the in-toto link. Default is the current directory (default [.])
      --step string              The name of the in-toto link
```
