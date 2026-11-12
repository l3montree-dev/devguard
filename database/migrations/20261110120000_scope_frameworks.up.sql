ALTER TABLE IF EXISTS public.frameworks_controls RENAME TO compliance_controls;

ALTER TABLE public.compliance_controls DROP CONSTRAINT IF EXISTS frameworks_controls_framework_control_id_unique;

ALTER TABLE public.compliance_controls DROP COLUMN IF EXISTS framework_control_id CASCADE;

ALTER TABLE public.compliance_controls ADD COLUMN IF NOT EXISTS control_hash text;

ALTER TABLE public.compliance_controls DROP CONSTRAINT IF EXISTS compliance_controls_control_hash_unique;
ALTER TABLE public.compliance_controls
    ADD CONSTRAINT compliance_controls_control_hash_unique UNIQUE (control_hash);

ALTER TABLE public.compliance_controls RENAME COLUMN parent_framework_control_id TO parent_control_id;

-- postures reference the control by its hash, the values are migrated in go (hash migration)
ALTER TABLE public.compliance_postures RENAME COLUMN framework_control_id TO control_hash;

ALTER INDEX IF EXISTS public.idx_frameworks_controls_parent_framework_control_id RENAME TO idx_compliance_controls_parent_control_id;

CREATE INDEX IF NOT EXISTS idx_compliance_controls_control_id ON public.compliance_controls (control_id);

CREATE TABLE IF NOT EXISTS public.scope_frameworks (
    id uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    framework text NOT NULL,
    org_id uuid NOT NULL,
    project_id uuid,
    asset_id uuid,
    CONSTRAINT uq_scope_frameworks_scope_framework UNIQUE NULLS NOT DISTINCT (org_id, project_id, asset_id, framework)
);

ALTER TABLE public.scope_frameworks DROP CONSTRAINT IF EXISTS fk_scope_frameworks_org;

ALTER TABLE ONLY public.scope_frameworks
    ADD CONSTRAINT fk_scope_frameworks_org FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE public.scope_frameworks DROP CONSTRAINT IF EXISTS fk_scope_frameworks_project;

ALTER TABLE ONLY public.scope_frameworks
    ADD CONSTRAINT fk_scope_frameworks_project FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;

ALTER TABLE public.scope_frameworks DROP CONSTRAINT IF EXISTS fk_scope_frameworks_asset;

ALTER TABLE ONLY public.scope_frameworks
    ADD CONSTRAINT fk_scope_frameworks_asset FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

-- framework <-> control hash
CREATE TABLE IF NOT EXISTS public.scope_framework_controls (
    scope_framework_id uuid NOT NULL,
    control_hash text NOT NULL,
    PRIMARY KEY (scope_framework_id, control_hash)
);

ALTER TABLE public.scope_framework_controls DROP CONSTRAINT IF EXISTS fk_scope_framework_controls_scope_framework;

ALTER TABLE ONLY public.scope_framework_controls
    ADD CONSTRAINT fk_scope_framework_controls_scope_framework FOREIGN KEY (scope_framework_id) REFERENCES public.scope_frameworks(id) ON DELETE CASCADE;

ALTER TABLE public.scope_framework_controls DROP CONSTRAINT IF EXISTS fk_scope_framework_controls_control;

ALTER TABLE ONLY public.scope_framework_controls
    ADD CONSTRAINT fk_scope_framework_controls_control FOREIGN KEY (control_hash) REFERENCES public.compliance_controls(control_hash) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_scope_framework_controls_control_hash ON public.scope_framework_controls (control_hash);
