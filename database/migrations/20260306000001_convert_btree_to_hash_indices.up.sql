-- Convert single-column equality-only indexes from btree to hash for better point-lookup performance.
-- Composite indexes, deleted_at indexes, and range-queried columns are left as btree.

-- component_dependencies (from initial migration)
DROP INDEX IF EXISTS public.asset_id_idx;
CREATE INDEX IF NOT EXISTS asset_id_idx ON public.component_dependencies USING hash (asset_id);

DROP INDEX IF EXISTS public.component_id_idx;
CREATE INDEX IF NOT EXISTS component_id_idx ON public.component_dependencies USING hash (component_id);

DROP INDEX IF EXISTS public.dependency_id_idx;
CREATE INDEX IF NOT EXISTS dependency_id_idx ON public.component_dependencies USING hash (dependency_id);

-- affected_components
DROP INDEX IF EXISTS public.idx_affected_components_p_url;
CREATE INDEX IF NOT EXISTS idx_affected_components_p_url ON public.affected_components USING hash (purl);

DROP INDEX IF EXISTS public.idx_affected_components_purl_without_version;
CREATE INDEX IF NOT EXISTS idx_affected_components_purl_without_version ON public.affected_components USING hash (purl);

DROP INDEX IF EXISTS public.idx_affected_components_version;
CREATE INDEX IF NOT EXISTS idx_affected_components_version ON public.affected_components USING hash (version);

-- organizations
DROP INDEX IF EXISTS public.idx_organizations_slug;
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON public.organizations USING hash (slug);

-- artifact_dependency_vulns
DROP INDEX IF EXISTS public.idx_artifact_dependency_vulns_dependency_vuln_id;
CREATE INDEX IF NOT EXISTS idx_artifact_dependency_vulns_dependency_vuln_id ON public.artifact_dependency_vulns USING hash (dependency_vuln_id);

-- artifact_license_risks
DROP INDEX IF EXISTS public.idx_artifact_license_risks_license_risk_id;
CREATE INDEX IF NOT EXISTS idx_artifact_license_risks_license_risk_id ON public.artifact_license_risks USING hash (license_risk_id);

-- component_dependencies (from add_missing_indices migration)
DROP INDEX IF EXISTS public.idx_component_dependencies_component_id;
CREATE INDEX IF NOT EXISTS idx_component_dependencies_component_id ON public.component_dependencies USING hash (component_id);

DROP INDEX IF EXISTS public.idx_component_dependencies_dependency_id;
CREATE INDEX IF NOT EXISTS idx_component_dependencies_dependency_id ON public.component_dependencies USING hash (dependency_id);

-- components
DROP INDEX IF EXISTS public.idx_components_project_key;
CREATE INDEX IF NOT EXISTS idx_components_project_key ON public.components USING hash (project_key);

-- dependency_vulns
DROP INDEX IF EXISTS public.idx_dependency_vulns_cve_id;
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_cve_id ON public.dependency_vulns USING hash (cve_id);

DROP INDEX IF EXISTS public.idx_dependency_vulns_component_purl;
CREATE INDEX IF NOT EXISTS idx_dependency_vulns_component_purl ON public.dependency_vulns USING hash (component_purl);

-- exploits
DROP INDEX IF EXISTS public.idx_exploits_cve_id;
CREATE INDEX IF NOT EXISTS idx_exploits_cve_id ON public.exploits USING hash (cve_id);

-- projects
DROP INDEX IF EXISTS public.idx_projects_parent_id;
CREATE INDEX IF NOT EXISTS idx_projects_parent_id ON public.projects USING hash (parent_id);

-- github_app_installations
DROP INDEX IF EXISTS public.idx_github_app_installations_org_id;
CREATE INDEX IF NOT EXISTS idx_github_app_installations_org_id ON public.github_app_installations USING hash (org_id);

-- gitlab_integrations
DROP INDEX IF EXISTS public.idx_gitlab_integrations_org_id;
CREATE INDEX IF NOT EXISTS idx_gitlab_integrations_org_id ON public.gitlab_integrations USING hash (org_id);

-- in_toto_links
DROP INDEX IF EXISTS public.idx_in_toto_links_pat_id;
CREATE INDEX IF NOT EXISTS idx_in_toto_links_pat_id ON public.in_toto_links USING hash (pat_id);

-- invitations
DROP INDEX IF EXISTS public.idx_invitations_organization_id;
CREATE INDEX IF NOT EXISTS idx_invitations_organization_id ON public.invitations USING hash (organization_id);

-- supply_chain
DROP INDEX IF EXISTS public.idx_supply_chain_asset_id;
CREATE INDEX IF NOT EXISTS idx_supply_chain_asset_id ON public.supply_chain USING hash (asset_id);

-- policies
DROP INDEX IF EXISTS public.idx_policies_organization_id;
CREATE INDEX IF NOT EXISTS idx_policies_organization_id ON public.policies USING hash (organization_id);

-- jira_integrations
DROP INDEX IF EXISTS public.idx_jira_integrations_org_id;
CREATE INDEX IF NOT EXISTS idx_jira_integrations_org_id ON public.jira_integrations USING hash (org_id);

-- license_risks
DROP INDEX IF EXISTS public.idx_license_risks_component_purl;
CREATE INDEX IF NOT EXISTS idx_license_risks_component_purl ON public.license_risks USING hash (component_purl);

-- webhook_integrations
DROP INDEX IF EXISTS public.idx_webhook_integrations_org_id;
CREATE INDEX IF NOT EXISTS idx_webhook_integrations_org_id ON public.webhook_integrations USING hash (org_id);

DROP INDEX IF EXISTS public.idx_webhook_integrations_project_id;
CREATE INDEX IF NOT EXISTS idx_webhook_integrations_project_id ON public.webhook_integrations USING hash (project_id);

-- releases
DROP INDEX IF EXISTS public.idx_releases_project_id;
CREATE INDEX IF NOT EXISTS idx_releases_project_id ON public.releases USING hash (project_id);

-- release_items
DROP INDEX IF EXISTS public.idx_release_items_child_release_id;
CREATE INDEX IF NOT EXISTS idx_release_items_child_release_id ON public.release_items USING hash (child_release_id);

DROP INDEX IF EXISTS public.idx_release_items_release_id;
CREATE INDEX IF NOT EXISTS idx_release_items_release_id ON public.release_items USING hash (release_id);

-- malicious_affected_components
DROP INDEX IF EXISTS public.idx_malicious_affected_purl;
CREATE INDEX IF NOT EXISTS idx_malicious_affected_purl ON public.malicious_affected_components USING hash (purl);

DROP INDEX IF EXISTS public.idx_malicious_affected_package_id;
CREATE INDEX IF NOT EXISTS idx_malicious_affected_package_id ON public.malicious_affected_components USING hash (malicious_package_id);

-- cve_relationships
DROP INDEX IF EXISTS public.idx_cve_relationships_target_cve;
CREATE INDEX IF NOT EXISTS idx_cve_relationships_target_cve ON public.cve_relationships USING hash (target_cve);

-- vex_rules
DROP INDEX IF EXISTS public.idx_vex_rule_asset;
CREATE INDEX IF NOT EXISTS idx_vex_rule_asset ON public.vex_rules USING hash (asset_id);

DROP INDEX IF EXISTS public.idx_vex_rule_cve;
CREATE INDEX IF NOT EXISTS idx_vex_rule_cve ON public.vex_rules USING hash (cve_id);

-- external_references
DROP INDEX IF EXISTS public.idx_external_refs_asset_id;
CREATE INDEX IF NOT EXISTS idx_external_refs_asset_id ON public.external_references USING hash (asset_id);

DROP INDEX IF EXISTS public.idx_external_refs_artifact;
CREATE INDEX IF NOT EXISTS idx_external_refs_artifact ON public.external_references USING hash (artifact_name);

-- pat fingerprint
DROP INDEX IF EXISTS public.idx_fingerprint;
CREATE INDEX IF NOT EXISTS idx_fingerprint ON public.pat USING hash (fingerprint);