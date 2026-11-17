ALTER TABLE public.compliance_components ADD COLUMN IF NOT EXISTS id uuid;
-- existing components keep their uuid as id so existing references stay valid
UPDATE public.compliance_components SET id = uuid WHERE id IS NULL;
ALTER TABLE public.compliance_components ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE public.compliance_components ALTER COLUMN id SET NOT NULL;

ALTER TABLE public.compliance_components DROP CONSTRAINT IF EXISTS compliance_components_pkey CASCADE;
ALTER TABLE public.compliance_components
    ADD CONSTRAINT compliance_components_pkey PRIMARY KEY (id);


ALTER TABLE public.compliance_components ADD COLUMN IF NOT EXISTS component_definition text;
ALTER TABLE public.compliance_components ADD COLUMN IF NOT EXISTS org_id uuid;
ALTER TABLE public.compliance_components ADD COLUMN IF NOT EXISTS project_id uuid;
ALTER TABLE public.compliance_components ADD COLUMN IF NOT EXISTS asset_id uuid;

ALTER TABLE public.compliance_components DROP CONSTRAINT IF EXISTS fk_compliance_components_org;

ALTER TABLE ONLY public.compliance_components
    ADD CONSTRAINT fk_compliance_components_org FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE public.compliance_components DROP CONSTRAINT IF EXISTS fk_compliance_components_project;

ALTER TABLE ONLY public.compliance_components
    ADD CONSTRAINT fk_compliance_components_project FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;

ALTER TABLE public.compliance_components DROP CONSTRAINT IF EXISTS fk_compliance_components_asset;

ALTER TABLE ONLY public.compliance_components
    ADD CONSTRAINT fk_compliance_components_asset FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE public.compliance_components DROP CONSTRAINT IF EXISTS uq_compliance_components_scope_definition_uuid;
ALTER TABLE public.compliance_components
    ADD CONSTRAINT uq_compliance_components_scope_definition_uuid UNIQUE NULLS NOT DISTINCT (org_id, project_id, asset_id, component_definition, uuid);

ALTER TABLE public.compliance_component_implements_controls DROP CONSTRAINT IF EXISTS fk_compliance_component_implements_controls_component;

ALTER TABLE ONLY public.compliance_component_implements_controls
    ADD CONSTRAINT fk_compliance_component_implements_controls_component FOREIGN KEY (compliance_component_id) REFERENCES public.compliance_components(id) ON DELETE CASCADE;
