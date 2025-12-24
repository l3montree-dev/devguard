-- Drop malicious packages tables
DROP INDEX IF EXISTS idx_malicious_affected_package_id;
DROP INDEX IF EXISTS idx_malicious_affected_version_fixed;
DROP INDEX IF EXISTS idx_malicious_affected_version_introduced;
DROP INDEX IF EXISTS idx_malicious_affected_semver_fixed;
DROP INDEX IF EXISTS idx_malicious_affected_semver_introduced;
DROP INDEX IF EXISTS idx_malicious_affected_version;
DROP INDEX IF EXISTS idx_malicious_affected_purl;
DROP TABLE IF EXISTS public.malicious_affected_components;
DROP TABLE IF EXISTS public.malicious_packages;

