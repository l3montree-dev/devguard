
ALTER TABLE ONLY public.asset_versions
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.assets
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.asset_versions
    DROP CONSTRAINT IF EXISTS fk_assets_asset_versions;    

ALTER TABLE ONLY public.asset_versions
    ADD CONSTRAINT fk_assets_asset_versions
    FOREIGN KEY (asset_id)
    REFERENCES public.assets(id)
    ON DELETE CASCADE;    

ALTER TABLE ONLY public.projects
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.assets
    DROP CONSTRAINT IF EXISTS fk_projects_assets;    

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT fk_projects_assets
    FOREIGN KEY (project_id)
    REFERENCES public.projects(id)
    ON DELETE CASCADE;

ALTER TABLE ONLY public.attestations
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.pat
    DROP COLUMN IF EXISTS deleted_at;   

ALTER TABLE ONLY public.cwes
    DROP COLUMN IF EXISTS deleted_at;    

ALTER TABLE ONLY public.gitlab_integrations
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.invitations
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.jira_integrations
    DROP COLUMN IF EXISTS deleted_at;        

ALTER TABLE ONLY public.webhook_integrations
    DROP COLUMN IF EXISTS deleted_at;     

ALTER TABLE ONLY public.webhook_integrations
    DROP CONSTRAINT IF EXISTS fk_projects_webhooks;

ALTER TABLE ONLY public.webhook_integrations
    ADD CONSTRAINT fk_projects_webhooks
    FOREIGN KEY (project_id)
    REFERENCES public.projects(id)
    ON DELETE CASCADE;         

ALTER TABLE ONLY public.organizations
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.vuln_events
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.projects
    DROP CONSTRAINT IF EXISTS fk_organizations_projects;

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_organizations_projects
    FOREIGN KEY (organization_id)
    REFERENCES public.organizations(id)
    ON DELETE CASCADE;    

ALTER TABLE ONLY public.dependency_vulns
    DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE ONLY public.releases
    DROP COLUMN IF EXISTS deleted_at;

