-- The semver range columns now store the order preserving encoding produced by
-- normalize.SemverToBytes instead of the pg_semver type.
-- Existing rows are not converted: hash migration v9 triggers a full vulndb import,
-- which repopulates these tables with the new encoding.
-- The columns are dropped and re-added instead of altered: the pg_semver shared library
-- is no longer shipped, and ALTER COLUMN TYPE / TRUNCATE (index rebuild) would need to load
-- it. DROP COLUMN only touches the catalog and removes dependent indexes.
ALTER TABLE public.affected_components
    DROP COLUMN semver_introduced,
    DROP COLUMN semver_fixed;

ALTER TABLE public.malicious_affected_components
    DROP COLUMN semver_introduced,
    DROP COLUMN semver_fixed;

DROP EXTENSION IF EXISTS semver;

TRUNCATE public.affected_components, public.cve_affected_component, public.malicious_affected_components;

ALTER TABLE public.affected_components
    ADD COLUMN semver_introduced bytea,
    ADD COLUMN semver_fixed      bytea;

ALTER TABLE public.malicious_affected_components
    ADD COLUMN semver_introduced bytea,
    ADD COLUMN semver_fixed      bytea;

CREATE INDEX IF NOT EXISTS idx_affected_component_purl_semver_range
    ON public.affected_components (purl, semver_introduced, semver_fixed)
    WHERE semver_introduced IS NOT NULL OR semver_fixed IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_malicious_affected_semver_introduced ON public.malicious_affected_components (semver_introduced);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_semver_fixed ON public.malicious_affected_components (semver_fixed);
