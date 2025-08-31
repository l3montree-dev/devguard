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


CREATE INDEX IF NOT EXISTS idx_component_dependencies_null_roots ON public.component_dependencies (asset_id, asset_version_name) WHERE component_purl IS NULL;


ALTER TABLE ONLY public.component_dependencies
    DROP CONSTRAINT IF EXISTS fk_asset_versions_components;

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_asset_versions_components FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;