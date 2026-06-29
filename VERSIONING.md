# Versioning Policy

DevGuard uses a modified semantic versioning scheme: **all components share the same major and minor version**, patch releases are independent per component.

## Compatibility Rule

> Any `vX.Y.*` release of one component is compatible with any `vX.Y.*` release of any other component.

| Component | Repository |
|-----------|------------|
| DevGuard (API/backend) | [devguard](https://github.com/l3montree-dev/devguard) |
| DevGuard Web (frontend) | [devguard-web](https://github.com/l3montree-dev/devguard-web) |
| Helm chart | [devguard-helm-chart](https://github.com/l3montree-dev/devguard-helm-chart) |
| CI Components | [devguard-ci-component](https://github.com/l3montree-dev/devguard-ci-component) |

## Rules

- **Major/Minor versions are synchronized.** A feature release bumps the major/minor version across all components at the same time.
- **Patch versions are independent.** A bug fix in only one component ships as a new patch for that component only — other components are not re-released.
- When upgrading, ensure all components share the **same minor version**. Patch versions do not need to match across components.

## Example

```
devguard      v1.7.5  ──┐
devguard-web  v1.7.2  ──┤  ✓  compatible (all minor 1.7)
Helm chart    v1.7.0  ──┘

devguard-web  v1.8.0
Helm chart    v1.7.0      ✗  incompatible (minor mismatch)
```

## Releases

Each component publishes its own GitHub releases. Release notes describe only what changed in that component. To check compatibility, verify all components you run share the same minor version — that is the only guarantee needed.
