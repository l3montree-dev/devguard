CREATE TABLE IF NOT EXISTS public.redmine_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name character varying(255) NOT NULL,
    org_id uuid,
    access_token text,
    url text NOT NULL,
    tracker_id INT NOT NULL,
    default_status_id INT DEFAULT NULL,
    close_status_id INT DEFAULT NULL,
    low_priority_id INT DEFAULT NULL,
    medium_priority_id INT DEFAULT NULL,
    high_priority_id INT DEFAULT NULL,
    critical_priority_id INT DEFAULT NULL,
    mermaid_integration TEXT DEFAULT 'none' CHECK (mermaid_integration IN ('none', 'macro', 'commonmark'))
);

ALTER TABLE ONLY public.redmine_integrations
    ADD CONSTRAINT redmine_integrations_pkey PRIMARY KEY (id);

ALTER TABLE public.redmine_integrations
    ADD CONSTRAINT fk_organizations_redmine_integrations
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_redmine_integrations_org_id ON public.redmine_integrations USING hash (org_id);
