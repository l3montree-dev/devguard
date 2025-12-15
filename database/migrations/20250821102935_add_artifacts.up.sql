TRUNCATE TABLE public.attestations;
ALTER TABLE public.attestations ADD COLUMN IF NOT EXISTS artifact_name TEXT NOT NULL;

CREATE TABLE IF NOT EXISTS public.artifacts (
    artifact_name TEXT NOT NULL,
    asset_version_name TEXT NOT NULL,
    asset_id UUID NOT NULL
);


CREATE TABLE IF NOT EXISTS public.artifact_component_dependencies (
    artifact_artifact_name TEXT NOT NULL,
    artifact_asset_version_name TEXT NOT NULL,
    artifact_asset_id UUID NOT NULL,
    component_dependency_id UUID NOT NULL
);

CREATE TABLE IF NOT EXISTS public.artifact_dependency_vulns (
    artifact_artifact_name TEXT NOT NULL,
    artifact_asset_version_name TEXT NOT NULL,
    artifact_asset_id UUID NOT NULL,
    dependency_vuln_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS public.artifact_license_risks (
    artifact_artifact_name TEXT NOT NULL,
    artifact_asset_version_name TEXT NOT NULL,
    artifact_asset_id UUID NOT NULL,
    license_risk_id TEXT NOT NULL
);


ALTER TABLE public.artifact_component_dependencies DROP CONSTRAINT IF EXISTS artifact_component_dependencies_pkey;
ALTER TABLE public.artifact_dependency_vulns DROP CONSTRAINT IF EXISTS artifact_dependency_vulns_pkey;
ALTER TABLE public.artifact_license_risks DROP CONSTRAINT IF EXISTS artifact_license_risks_pkey;
ALTER TABLE public.artifact_dependency_vulns DROP CONSTRAINT IF EXISTS fk_artifact_dependency_vulns_artifact;
ALTER TABLE public.artifact_license_risks DROP CONSTRAINT IF EXISTS fk_artifact_license_risks_artifact;
ALTER TABLE public.attestations DROP CONSTRAINT IF EXISTS fk_attestations_artifact;
ALTER TABLE public.artifact_component_dependencies DROP CONSTRAINT IF EXISTS fk_artifact_component_dependencies_artifact;
ALTER TABLE public.asset_versions DROP CONSTRAINT IF EXISTS fk_asset_versions_artifact;
ALTER TABLE public.artifact_license_risks DROP CONSTRAINT IF EXISTS fk_artifact_license_risks_license_risk;
ALTER TABLE public.artifact_dependency_vulns DROP CONSTRAINT IF EXISTS fk_artifact_dependency_vulns_dependency_vuln;
ALTER TABLE public.artifact_component_dependencies DROP CONSTRAINT IF EXISTS fk_artifact_component_dependencies_component_dependency;

ALTER TABLE public.artifacts DROP CONSTRAINT IF EXISTS fk_artifacts_asset_versions;
ALTER TABLE public.artifacts DROP CONSTRAINT IF EXISTS artifacts_pkey;
ALTER TABLE public.license_risks DROP CONSTRAINT IF EXISTS license_risks_pkey;


ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_pkey PRIMARY KEY (artifact_name, asset_version_name, asset_id);



ALTER TABLE ONLY public.artifact_component_dependencies
    ADD CONSTRAINT artifact_component_dependencies_pkey PRIMARY KEY (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, component_dependency_id);


ALTER TABLE ONLY public.artifact_dependency_vulns
    ADD CONSTRAINT artifact_dependency_vulns_pkey PRIMARY KEY (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, dependency_vuln_id);


ALTER TABLE ONLY public.artifact_license_risks
    ADD CONSTRAINT artifact_license_risks_pkey PRIMARY KEY (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, license_risk_id);

ALTER TABLE public.license_risks ADD CONSTRAINT license_risks_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.artifact_component_dependencies
    ADD CONSTRAINT fk_artifact_component_dependencies_artifact FOREIGN KEY
    (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id)
    REFERENCES public.artifacts (artifact_name, asset_version_name, asset_id)
    ON DELETE CASCADE;


ALTER TABLE ONLY public.artifact_component_dependencies
    ADD CONSTRAINT fk_artifact_component_dependencies_component_dependency FOREIGN KEY
    (component_dependency_id)
    REFERENCES public.component_dependencies (id)
    ON DELETE CASCADE;


ALTER TABLE ONLY public.artifact_dependency_vulns
    ADD CONSTRAINT fk_artifact_dependency_vulns_artifact FOREIGN KEY
    (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id)
    REFERENCES public.artifacts (artifact_name, asset_version_name, asset_id)
    ON DELETE CASCADE;

ALTER TABLE ONLY public.artifact_dependency_vulns
    ADD CONSTRAINT fk_artifact_dependency_vulns_dependency_vuln FOREIGN KEY
    (dependency_vuln_id)
    REFERENCES public.dependency_vulns (id)
    ON DELETE CASCADE
    ON UPDATE CASCADE;


ALTER TABLE ONLY public.artifact_license_risks
    ADD CONSTRAINT fk_artifact_license_risks_artifact FOREIGN KEY
    (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id)
    REFERENCES public.artifacts (artifact_name, asset_version_name, asset_id)
    ON DELETE CASCADE;

ALTER TABLE ONLY public.artifact_license_risks
    ADD CONSTRAINT fk_artifact_license_risks_license_risk FOREIGN KEY
    (license_risk_id)
    REFERENCES public.license_risks (id)
    ON DELETE CASCADE;


ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT fk_artifacts_asset_versions FOREIGN KEY
    (asset_version_name, asset_id)
    REFERENCES public.asset_versions (name, asset_id)
    ON DELETE CASCADE;


--- Read all scanner_ids of the component_dependencies and create corresponding artifacts ---
INSERT INTO public.artifacts (asset_id, asset_version_name, artifact_name)
SELECT DISTINCT
    t.asset_id,
    t.asset_version_name,
    trim(sid) AS artifact_name
FROM public.component_dependencies t,
LATERAL regexp_split_to_table(t.scanner_ids, '\s+') sid
WHERE t.asset_version_name IS NOT NULL
ON CONFLICT (asset_id, asset_version_name, artifact_name) DO NOTHING;

--- Recreate the relationship ---

INSERT INTO public.artifact_component_dependencies (
    artifact_artifact_name,
    artifact_asset_version_name,
    artifact_asset_id,
    component_dependency_id
)
SELECT DISTINCT
    a.artifact_name,
    a.asset_version_name,
    a.asset_id,
    cd.id
FROM public.component_dependencies cd
JOIN LATERAL regexp_split_to_table(cd.scanner_ids, '\s+') sid ON true
JOIN public.artifacts a
  ON a.asset_id = cd.asset_id
 AND a.asset_version_name = cd.asset_version_name
 AND a.artifact_name = trim(sid)
ON CONFLICT (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, component_dependency_id) DO NOTHING;


INSERT INTO public.artifact_dependency_vulns (
    artifact_artifact_name,
    artifact_asset_version_name,
    artifact_asset_id,
    dependency_vuln_id
)
SELECT DISTINCT
        a.artifact_name AS artifact_artifact_name,
        a.asset_version_name,
        a.asset_id,
        dv.id AS dependency_vuln_id
FROM public.dependency_vulns dv
JOIN LATERAL regexp_split_to_table(dv.scanner_ids, '\s+') sid ON true
JOIN public.artifacts a
    ON a.asset_id = dv.asset_id
 AND a.asset_version_name = dv.asset_version_name
 AND a.artifact_name = trim(sid)
ON CONFLICT (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, dependency_vuln_id) DO NOTHING;


INSERT INTO public.artifact_license_risks (
    artifact_artifact_name,
    artifact_asset_version_name,
    artifact_asset_id,
    license_risk_id
)
SELECT DISTINCT
        a.artifact_name AS artifact_artifact_name,
        a.asset_version_name,
        a.asset_id,
        lr.id AS license_risk_id
FROM public.license_risks lr
JOIN LATERAL regexp_split_to_table(lr.scanner_ids, '\s+') sid ON true
JOIN public.artifacts a
    ON a.asset_id = lr.asset_id
 AND a.asset_version_name = lr.asset_version_name
 AND a.artifact_name = trim(sid)
ON CONFLICT (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, license_risk_id) DO NOTHING;


ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT fk_attestations_artifact FOREIGN KEY (artifact_name, asset_version_name, asset_id)
    REFERENCES public.artifacts (artifact_name, asset_version_name, asset_id)
    ON DELETE CASCADE;

ALTER TABLE public.dependency_vulns DROP COLUMN IF EXISTS scanner_ids;
ALTER TABLE public.component_dependencies DROP COLUMN IF EXISTS scanner_ids;
ALTER TABLE public.license_risks DROP COLUMN IF EXISTS scanner_ids;