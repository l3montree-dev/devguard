ALTER TABLE public.artifact_risk_history
DROP COLUMN IF EXISTS cve_purl_fixable_critical,
DROP COLUMN IF EXISTS cve_purl_fixable_high,
DROP COLUMN IF EXISTS cve_purl_fixable_medium,
DROP COLUMN IF EXISTS cve_purl_fixable_low,
DROP COLUMN IF EXISTS fixable_critical,
DROP COLUMN IF EXISTS fixable_high,
DROP COLUMN IF EXISTS fixable_medium,
DROP COLUMN IF EXISTS fixable_low;
