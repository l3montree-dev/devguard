ALTER TABLE public.artifact_risk_history
ADD COLUMN IF NOT EXISTS cve_purl_low INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_medium INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_high INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_critical INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_low_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_medium_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_high_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_critical_cvss INTEGER DEFAULT 0;

UPDATE public.artifact_risk_history SET
    cve_purl_low = low,
    cve_purl_medium = medium,
    cve_purl_high = high,
    cve_purl_critical = critical,
    cve_purl_low_cvss = low_cvss,
    cve_purl_medium_cvss = medium_cvss,
    cve_purl_high_cvss = high_cvss,
    cve_purl_critical_cvss = critical_cvss;

ALTER TABLE public.project_risk_history
ADD COLUMN IF NOT EXISTS cve_purl_low INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_medium INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_high INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_critical INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_low_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_medium_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_high_cvss INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_critical_cvss INTEGER DEFAULT 0;

UPDATE public.project_risk_history SET
    cve_purl_low = low,
    cve_purl_medium = medium,
    cve_purl_high = high,
    cve_purl_critical = critical,
    cve_purl_low_cvss = low_cvss,
    cve_purl_medium_cvss = medium_cvss,
    cve_purl_high_cvss = high_cvss,
    cve_purl_critical_cvss = critical_cvss;
