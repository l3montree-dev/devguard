ALTER TABLE public.vuln_events
    ADD COLUMN IF NOT EXISTS compliance_posture_id uuid REFERENCES public.compliance_postures(id) ON DELETE CASCADE;

-- Drop the old constraint and recreate it to also allow compliance_posture_id as a valid parent
ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS one_vuln_parent;
ALTER TABLE public.vuln_events ADD CONSTRAINT one_vuln_parent CHECK (
  (dependency_vuln_id   IS NOT NULL)::int +
  (license_risk_id      IS NOT NULL)::int +
  (first_party_vuln_id  IS NOT NULL)::int +
  (compliance_posture_id IS NOT NULL)::int = 1
);




CREATE TABLE IF NOT EXISTS public.compliance_postures (
    id uuid NOT NULL,
    message text,
    state text DEFAULT 'open'::text NOT NULL,
    last_detected timestamp with time zone DEFAULT now() NOT NULL,
    ticket_id text,
    ticket_url text,
    manual_ticket_creation boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    asset_version_name text,
    asset_id uuid,
    project_id uuid,
    org_id uuid NOT NULL,
    framework_control_id text NOT NULL
);

ALTER TABLE ONLY public.compliance_postures
    ADD CONSTRAINT compliance_postures_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.compliance_postures
    ADD CONSTRAINT fk_compliance_postures_control FOREIGN KEY (framework_control_id) REFERENCES public.frameworks_controls(framework_control_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.compliance_postures
    ADD CONSTRAINT fk_compliance_postures_asset FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.compliance_postures
    ADD CONSTRAINT fk_compliance_postures_project FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.compliance_postures
    ADD CONSTRAINT fk_compliance_postures_org FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;
