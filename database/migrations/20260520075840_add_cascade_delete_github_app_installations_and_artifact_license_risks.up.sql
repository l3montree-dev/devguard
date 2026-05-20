ALTER TABLE public.github_app_installations
    DROP CONSTRAINT IF EXISTS fk_organizations_github_app_installations;

ALTER TABLE public.github_app_installations
    ADD CONSTRAINT fk_organizations_github_app_installations
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE public.artifact_license_risks
    DROP CONSTRAINT IF EXISTS artifact_license_risks_new_license_risk_id_fkey;

ALTER TABLE public.artifact_license_risks
    DROP CONSTRAINT IF EXISTS artifact_license_risks_license_risk_id_fkey;

ALTER TABLE public.artifact_license_risks
    ADD CONSTRAINT artifact_license_risks_license_risk_id_fkey
        FOREIGN KEY (license_risk_id) REFERENCES public.license_risks(id) ON DELETE CASCADE;