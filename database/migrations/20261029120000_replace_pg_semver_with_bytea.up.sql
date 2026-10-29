-- The semver range columns now store the order preserving encoding produced by
-- normalize.SemverToBytes instead of the pg_semver type.
-- Existing rows are not converted: hash migration v9 triggers a full vulndb import,
-- which repopulates these tables with the new encoding.
TRUNCATE public.affected_components, public.cve_affected_component, public.malicious_affected_components;

ALTER TABLE public.affected_components
    ALTER COLUMN semver_introduced TYPE bytea USING NULL,
    ALTER COLUMN semver_fixed      TYPE bytea USING NULL;

ALTER TABLE public.malicious_affected_components
    ALTER COLUMN semver_introduced TYPE bytea USING NULL,
    ALTER COLUMN semver_fixed      TYPE bytea USING NULL;

DROP EXTENSION IF EXISTS semver;
