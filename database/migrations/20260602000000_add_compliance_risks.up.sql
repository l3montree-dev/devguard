CREATE TABLE IF NOT EXISTS public.compliance_risks (
    id uuid NOT NULL,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    message text,
    scanner_ids text NOT NULL DEFAULT '',
    state text DEFAULT 'open' NOT NULL,
    last_detected timestamp with time zone DEFAULT now() NOT NULL,
    ticket_id text,
    ticket_url text,
    manual_ticket_creation boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    policy_id text NOT NULL,
    CONSTRAINT compliance_risks_pkey PRIMARY KEY (id),
    CONSTRAINT fk_compliance_risks_asset_versions FOREIGN KEY (asset_version_name, asset_id)
        REFERENCES public.asset_versions (name, asset_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.artifact_compliance_risks (
    artifact_artifact_name text NOT NULL,
    artifact_asset_version_name text NOT NULL,
    artifact_asset_id uuid NOT NULL,
    compliance_risk_id uuid NOT NULL,
    CONSTRAINT artifact_compliance_risks_pkey PRIMARY KEY (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, compliance_risk_id),
    CONSTRAINT fk_artifact_compliance_risks_artifact FOREIGN KEY (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id)
        REFERENCES public.artifacts (artifact_name, asset_version_name, asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_artifact_compliance_risks_compliance_risk FOREIGN KEY (compliance_risk_id)
        REFERENCES public.compliance_risks (id) ON DELETE CASCADE
);

-- Add compliance_risk_id column to vuln_events
ALTER TABLE public.vuln_events
    ADD COLUMN IF NOT EXISTS compliance_risk_id uuid;

ALTER TABLE public.vuln_events
    ADD CONSTRAINT fk_vuln_events_compliance_risk FOREIGN KEY (compliance_risk_id)
        REFERENCES public.compliance_risks (id) ON DELETE CASCADE;

-- Drop old one_vuln_parent check (only 3 columns) and replace with updated version including compliance_risk_id
ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS one_vuln_parent;

ALTER TABLE public.vuln_events ADD CONSTRAINT one_vuln_parent CHECK (
    (dependency_vuln_id  IS NOT NULL)::int +
    (license_risk_id     IS NOT NULL)::int +
    (first_party_vuln_id IS NOT NULL)::int +
    (compliance_risk_id  IS NOT NULL)::int = 1
);

CREATE INDEX IF NOT EXISTS idx_compliance_risks_asset_version
    ON public.compliance_risks (asset_version_name, asset_id);

CREATE INDEX IF NOT EXISTS idx_artifact_compliance_risks_compliance_risk_id
    ON public.artifact_compliance_risks (compliance_risk_id);
