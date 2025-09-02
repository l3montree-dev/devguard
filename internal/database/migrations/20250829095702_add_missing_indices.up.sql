-- Primary foreign key indexes for artifact_component_dependencies
CREATE INDEX IF NOT EXISTS idx_artifact_component_dependencies_component_dependency_id 
ON public.artifact_component_dependencies (component_dependency_id);

CREATE INDEX IF NOT EXISTS idx_artifact_component_dependencies_artifact 
ON public.artifact_component_dependencies (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id);

-- Primary foreign key indexes for artifact_dependency_vulns
CREATE INDEX IF NOT EXISTS idx_artifact_dependency_vulns_dependency_vuln_id 
ON public.artifact_dependency_vulns (dependency_vuln_id);

CREATE INDEX IF NOT EXISTS idx_artifact_dependency_vulns_artifact 
ON public.artifact_dependency_vulns (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id);

-- Primary foreign key indexes for artifact_license_risks
CREATE INDEX IF NOT EXISTS idx_artifact_license_risks_license_risk_id 
ON public.artifact_license_risks (license_risk_id);

CREATE INDEX IF NOT EXISTS idx_artifact_license_risks_artifact 
ON public.artifact_license_risks (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id);

-- Index for artifacts table foreign key to asset_versions
CREATE INDEX IF NOT EXISTS idx_artifacts_asset_version 
ON public.artifacts (asset_version_name, asset_id);

-- Index for attestations foreign key to artifacts
CREATE INDEX IF NOT EXISTS idx_attestations_artifact 
ON public.attestations (artifact_name, asset_version_name, asset_id);

-- Additional performance indexes for component_dependencies (for your recursive query)
CREATE INDEX IF NOT EXISTS idx_component_dependencies_asset_lookup 
ON public.component_dependencies (asset_id, asset_version_name);

CREATE INDEX IF NOT EXISTS idx_component_dependencies_component_purl 
ON public.component_dependencies (component_purl);

CREATE INDEX IF NOT EXISTS idx_component_dependencies_dependency_purl 
ON public.component_dependencies (dependency_purl);

CREATE INDEX IF NOT EXISTS idx_component_dependencies_recursive_lookup 
ON public.component_dependencies (asset_id, asset_version_name, component_purl);

-- Index for dependency_vulns lookups
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_asset_lookup 
ON public.dependency_vulns (asset_id, asset_version_name);

-- Index for license_risks lookups
CREATE INDEX IF NOT EXISTS idx_license_risks_asset_lookup 
ON public.license_risks (asset_id, asset_version_name);


CREATE INDEX IF NOT EXISTS idx_component_dependencies_null_roots ON public.public.component_dependencies (asset_id, asset_version_name) WHERE component_purl IS NULL;


ALTER TABLE ONLY public.component_dependencies
    DROP CONSTRAINT IF EXISTS fk_asset_versions_components;

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_asset_versions_components FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON public.DELETE CASCADE;


CREATE INDEX IF NOT EXISTS idx_components_project_key ON public.components (project_key);
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_cve_id ON public.dependency_vulns (cve_id);
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_component_purl ON public.dependency_vulns (component_purl);
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_cve_id ON public.dependency_vulns (cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON public.exploits (cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_events_flaw_id ON public.vuln_events (flaw_id);
CREATE INDEX IF NOT EXISTS idx_projects_parent_id ON public.projects (parent_id);
CREATE INDEX IF NOT EXISTS idx_organizations_organization_id ON public.organizations (organization_id);
CREATE INDEX IF NOT EXISTS idx_github_app_installations_org_id ON public.github_app_installations (org_id);
CREATE INDEX IF NOT EXISTS idx_gitlab_integrations_org_id ON public.gitlab_integrations (org_id);
CREATE INDEX IF NOT EXISTS idx_in_toto_links_pat_id ON public.in_toto_links (pat_id);
CREATE INDEX IF NOT EXISTS idx_invitations_organization_id ON public.invitations (organization_id);
CREATE INDEX IF NOT EXISTS idx_supply_chain_asset_version_name_asset_id ON public.supply_chain (asset_version_name, asset_id);
CREATE INDEX IF NOT EXISTS idx_supply_chain_asset_id ON public.supply_chain (asset_id);
CREATE INDEX IF NOT EXISTS idx_supply_chain_asset_id ON public.supply_chain (asset_id);
CREATE INDEX IF NOT EXISTS idx_first_party_vulnerabilities_asset_version_name_asset_id ON public.first_party_vulnerabilities (asset_version_name, asset_id);
CREATE INDEX IF NOT EXISTS idx_policies_organization_id ON public.policies (organization_id);
CREATE INDEX IF NOT EXISTS idx_jira_integrations_org_id ON public.jira_integrations (org_id);
CREATE INDEX IF NOT EXISTS idx_license_risks_component_purl ON public.license_risks (component_purl);
CREATE INDEX IF NOT EXISTS idx_webhook_integrations_org_id ON public.webhook_integrations (org_id);
CREATE INDEX IF NOT EXISTS idx_webhook_integrations_project_id ON public.webhook_integrations (project_id);
CREATE INDEX IF NOT EXISTS idx_releases_project_id ON public.releases (project_id);
CREATE INDEX IF NOT EXISTS idx_release_items_asset_version_name_artifact_name_asset_id ON public.release_items (asset_version_name, artifact_name, asset_id);
CREATE INDEX IF NOT EXISTS idx_release_items_child_release_id ON public.release_items (child_release_id);
CREATE INDEX IF NOT EXISTS idx_release_items_release_id ON public.release_items (release_id);
CREATE INDEX IF NOT EXISTS idx_release_items_child_release_id ON public.release_items (child_release_id);
CREATE INDEX IF NOT EXISTS idx_release_items_release_id ON public.release_items (release_id);