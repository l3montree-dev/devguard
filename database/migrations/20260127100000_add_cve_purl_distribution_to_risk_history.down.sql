ALTER TABLE public.artifact_risk_history
DROP COLUMN IF EXISTS cve_purl_low,
DROP COLUMN IF EXISTS cve_purl_medium,
DROP COLUMN IF EXISTS cve_purl_high,
DROP COLUMN IF EXISTS cve_purl_critical,
DROP COLUMN IF EXISTS cve_purl_low_cvss,
DROP COLUMN IF EXISTS cve_purl_medium_cvss,
DROP COLUMN IF EXISTS cve_purl_high_cvss,
DROP COLUMN IF EXISTS cve_purl_critical_cvss;

ALTER TABLE public.project_risk_history
DROP COLUMN IF EXISTS cve_purl_low,
DROP COLUMN IF EXISTS cve_purl_medium,
DROP COLUMN IF EXISTS cve_purl_high,
DROP COLUMN IF EXISTS cve_purl_critical,
DROP COLUMN IF EXISTS cve_purl_low_cvss,
DROP COLUMN IF EXISTS cve_purl_medium_cvss,
DROP COLUMN IF EXISTS cve_purl_high_cvss,
DROP COLUMN IF EXISTS cve_purl_critical_cvss;
