{ self }:
let
  # Nix has no way to know a checkout's branch/tag from source content alone
  # (self excludes .git, and rev/shortRev are commit-only) - only CI knows
  # this, via an env var. Requires `nix build --impure`; falls back to the
  # commit hash for local/non-CI builds.
  refName =
    let
      githubRef = builtins.getEnv "GITHUB_REF_NAME";
      gitlabRef = builtins.getEnv "CI_COMMIT_REF_NAME";
    in
    if githubRef != "" then githubRef
    else if gitlabRef != "" then gitlabRef
    else "";
in
rec {
  version = if refName != "" then refName else self.shortRev or self.dirtyShortRev or "dev";
  commit = self.rev or self.dirtyRev or "unknown";
  buildDate = "1970-01-01T00:00:00+0000"; # fixed → reproducible layers
}
