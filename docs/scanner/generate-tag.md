## generate-tag

Generate a tag for an image based on its contents

### Synopsis

This command generates a tag, artifact name, and URL-encoded artifact name for a given image based on its contents and the provided parameters such as upstream version, architecture, and image type.

```shell
devguard-scanner generate-tag [flags]
```

### Examples

```shell
  # Generate tag with upstream version and architecture
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/my-image

  # Generate tag with variant
  devguard-scanner generate-tag --upstreamVersion 2.0.0 --architecture arm64 --imageVariant alpine --imagePath registry.io/app
```

### Options

```shell
      --architecture string      Target architecture(s) for the image (required). Can be specified multiple times or as comma-separated values. (default "amd64")
      --defaultRef string        The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                     help for generate-tag
      --imagePath string         Path to the image file (required)
      --imageSuffix string       Suffix to append to the image tag
      --imageVariant string      Type of the image (e.g., minimal, full, alpine)
      --isTag                    If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --ref string               The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --upstreamVersion string   Upstream version of the software
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
