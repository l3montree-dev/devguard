## login

Log in to a remote registry

### Synopsis

Log in to a remote registry using username and password.

Provide the registry URL as a positional argument. Both --username and --password
are required by this command. Credentials will be used to authenticate with the
registry (for example to pull/push images) and may be cached per the underlying
container runtime configuration.

```shell
devguard-scanner login [flags] <registry>
```

### Examples

```shell
  # Log in to GitHub Container Registry
  devguard-scanner login -u myuser -p mypass ghcr.io

  # Log in to Docker Hub
  devguard-scanner login -u myuser -p mypass docker.io

  # Log in to a private registry
  devguard-scanner login -u admin -p secret registry.example.com
```

### Options

```shell
  -h, --help              help for login
  -p, --password string   The password to authenticate to the container registry (required)
  -u, --username string   The username to authenticate to the container registry (required)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
