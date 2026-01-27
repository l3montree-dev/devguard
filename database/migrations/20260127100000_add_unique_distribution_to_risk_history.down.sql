ALTER TABLE public.artifact_risk_history
DROP COLUMN IF EXISTS unique_low,
DROP COLUMN IF EXISTS unique_medium,
DROP COLUMN IF EXISTS unique_high,
DROP COLUMN IF EXISTS unique_critical,
DROP COLUMN IF EXISTS unique_low_cvss,
DROP COLUMN IF EXISTS unique_medium_cvss,
DROP COLUMN IF EXISTS unique_high_cvss,
DROP COLUMN IF EXISTS unique_critical_cvss;

ALTER TABLE public.project_risk_history
DROP COLUMN IF EXISTS unique_low,
DROP COLUMN IF EXISTS unique_medium,
DROP COLUMN IF EXISTS unique_high,
DROP COLUMN IF EXISTS unique_critical,
DROP COLUMN IF EXISTS unique_low_cvss,
DROP COLUMN IF EXISTS unique_medium_cvss,
DROP COLUMN IF EXISTS unique_high_cvss,
DROP COLUMN IF EXISTS unique_critical_cvss;
