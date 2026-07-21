ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS one_vuln_parent;
ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS vuln_events_security_advisory_id_fkey;

ALTER TABLE public.advisories
    ADD COLUMN IF NOT EXISTS new_id UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE public.advisories_affected_packages
    ADD COLUMN IF NOT EXISTS new_advisory_id UUID;

UPDATE public.advisories_affected_packages j
   SET new_advisory_id = a.new_id
  FROM public.advisories a
 WHERE a.id = j.advisory_id;

ALTER TABLE public.vuln_events ADD COLUMN IF NOT EXISTS security_advisory_id BIGINT;
ALTER TABLE public.vuln_events ADD COLUMN IF NOT EXISTS new_security_advisory_id UUID;

UPDATE public.vuln_events e
   SET new_security_advisory_id = a.new_id
  FROM public.advisories a
 WHERE a.id = e.security_advisory_id;

ALTER TABLE public.advisories_affected_packages
    DROP CONSTRAINT IF EXISTS advisories_affected_packages_pkey;
ALTER TABLE public.advisories_affected_packages DROP COLUMN advisory_id;
ALTER TABLE public.advisories_affected_packages RENAME COLUMN new_advisory_id TO advisory_id;
ALTER TABLE public.advisories_affected_packages ALTER COLUMN advisory_id SET NOT NULL;

ALTER TABLE public.vuln_events DROP COLUMN security_advisory_id;
ALTER TABLE public.vuln_events RENAME COLUMN new_security_advisory_id TO security_advisory_id;

ALTER TABLE public.advisories DROP CONSTRAINT advisories_pkey;
ALTER TABLE public.advisories DROP COLUMN id;
ALTER TABLE public.advisories RENAME COLUMN new_id TO id;
ALTER TABLE public.advisories ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.advisories ADD PRIMARY KEY (id);

ALTER TABLE public.advisories_affected_packages
    ADD CONSTRAINT advisories_affected_packages_pkey
        PRIMARY KEY (advisory_id, affected_package_id),
    ADD CONSTRAINT advisories_affected_packages_advisory_id_fkey
        FOREIGN KEY (advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;

ALTER TABLE public.vuln_events
    ADD CONSTRAINT vuln_events_security_advisory_id_fkey
        FOREIGN KEY (security_advisory_id) REFERENCES public.advisories(id) ON DELETE CASCADE;

ALTER TABLE public.vuln_events ADD CONSTRAINT one_vuln_parent CHECK (
  (dependency_vuln_id    IS NOT NULL)::int +
  (license_risk_id       IS NOT NULL)::int +
  (first_party_vuln_id   IS NOT NULL)::int +
  (compliance_posture_id IS NOT NULL)::int +
  (security_advisory_id  IS NOT NULL)::int = 1
);
