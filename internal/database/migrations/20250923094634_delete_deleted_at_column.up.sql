-- Delete soft-deleted rows in asset_versions
DELETE FROM public.asset_versions
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in assets
DELETE FROM public.assets
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in projects
DELETE FROM public.projects
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in attestations
DELETE FROM public.attestations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in pat
DELETE FROM public.pat
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in cwes
DELETE FROM public.cwes
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in gitlab_integrations
DELETE FROM public.gitlab_integrations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in invitations
DELETE FROM public.invitations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in jira_integrations
DELETE FROM public.jira_integrations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in webhook_integrations
DELETE FROM public.webhook_integrations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in organizations
DELETE FROM public.organizations
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in vuln_events
DELETE FROM public.vuln_events
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in dependency_vulns
DELETE FROM public.dependency_vulns
WHERE deleted_at IS NOT NULL;

-- Delete soft-deleted rows in releases
DELETE FROM public.releases
WHERE deleted_at IS NOT NULL;

--- Now drop everything ---

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

