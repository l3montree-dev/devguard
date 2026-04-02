ALTER TABLE public.artifact_risk_history
ADD COLUMN IF NOT EXISTS fixable_low INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS fixable_medium INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS fixable_high INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS fixable_critical INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_fixable_low INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_fixable_medium INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_fixable_high INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS cve_purl_fixable_critical INTEGER DEFAULT 0;

UPDATE public.artifact_risk_history
SET
    fixable_low = COALESCE(fixable_low, 0),
    fixable_medium = COALESCE(fixable_medium, 0),
    fixable_high = COALESCE(fixable_high, 0),
    fixable_critical = COALESCE(fixable_critical, 0),
    cve_purl_fixable_low = COALESCE(cve_purl_fixable_low, 0),
    cve_purl_fixable_medium = COALESCE(cve_purl_fixable_medium, 0),
    cve_purl_fixable_high = COALESCE(cve_purl_fixable_high, 0),
    cve_purl_fixable_critical = COALESCE(cve_purl_fixable_critical, 0);
