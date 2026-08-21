ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS message;
ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS last_detected;
ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS effort;
ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS risk_assessment;
ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS priority;
ALTER TABLE public.dependency_vulns RENAME COLUMN raw_risk_assessment TO risk_assessment;

ALTER TABLE public.license_risks DROP COLUMN IF EXISTS message;
ALTER TABLE public.license_risks DROP COLUMN IF EXISTS last_detected;

ALTER TABLE public.compliance_postures DROP COLUMN IF EXISTS message;
ALTER TABLE public.compliance_postures DROP COLUMN IF EXISTS last_detected;

ALTER TABLE public.first_party_vulnerabilities DROP COLUMN IF EXISTS last_detected;
-- NOTE: do NOT drop `message` from first_party_vulnerabilities -- it stays, now owned directly by the FirstPartyVuln Go struct instead of via the embedded base struct.

ALTER TABLE public.advisories DROP COLUMN IF EXISTS message;
ALTER TABLE public.advisories DROP COLUMN IF EXISTS last_detected;
