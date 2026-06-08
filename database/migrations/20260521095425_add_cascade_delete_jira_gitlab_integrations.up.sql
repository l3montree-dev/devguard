ALTER TABLE public.jira_integrations
    DROP CONSTRAINT IF EXISTS fk_organizations_jira_integrations;

ALTER TABLE public.jira_integrations
    ADD CONSTRAINT fk_organizations_jira_integrations
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE public.gitlab_integrations
    DROP CONSTRAINT IF EXISTS fk_organizations_git_lab_integrations;

ALTER TABLE public.gitlab_integrations
    ADD CONSTRAINT fk_organizations_git_lab_integrations
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;
