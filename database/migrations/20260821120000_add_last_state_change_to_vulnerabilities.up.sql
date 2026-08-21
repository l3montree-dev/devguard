ALTER TABLE public.dependency_vulns ADD COLUMN IF NOT EXISTS last_state_change timestamp with time zone DEFAULT now() NOT NULL;
ALTER TABLE public.first_party_vulnerabilities ADD COLUMN IF NOT EXISTS last_state_change timestamp with time zone DEFAULT now() NOT NULL;
ALTER TABLE public.license_risks ADD COLUMN IF NOT EXISTS last_state_change timestamp with time zone DEFAULT now() NOT NULL;
ALTER TABLE public.compliance_postures ADD COLUMN IF NOT EXISTS last_state_change timestamp with time zone DEFAULT now() NOT NULL;
