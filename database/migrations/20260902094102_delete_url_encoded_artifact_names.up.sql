-- Artifacts can only ever be looked up by their url-decoded name (see
-- shared.GetArtifactName / normalize.ArtifactName), so any artifact whose
-- stored name still contains a percent-encoded escape sequence (e.g.
-- "pkg%3Aoci%2F%40opencode%2Fduckdb") is unreachable through the API: a
-- request for it always resolves to a different artifact instead (see
-- https://github.com/l3montree-dev/devguard/issues/2579). These rows are
-- dead data - delete them. Dependent rows (artifact_dependency_vulns,
-- artifact_license_risks, artifact_risk_histories) are removed via
-- ON DELETE CASCADE.
DELETE FROM public.artifacts
WHERE artifact_name ~ '%[0-9A-Fa-f]{2}';
