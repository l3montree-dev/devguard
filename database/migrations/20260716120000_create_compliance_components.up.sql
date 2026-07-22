CREATE TABLE IF NOT EXISTS public.compliance_components (
    uuid uuid PRIMARY KEY NOT NULL,
    title text NOT NULL,
    description text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.compliance_component_implements_controls (
    framework_control_id text NOT NULL,
    compliance_component_id uuid NOT NULL,
    description text NOT NULL,
    PRIMARY KEY (framework_control_id, compliance_component_id)
);

ALTER TABLE public.compliance_component_implements_controls DROP CONSTRAINT IF EXISTS fk_compliance_component_implements_controls_control;

ALTER TABLE ONLY public.compliance_component_implements_controls
    ADD CONSTRAINT fk_compliance_component_implements_controls_control FOREIGN KEY (framework_control_id) REFERENCES public.frameworks_controls(framework_control_id) ON DELETE CASCADE;

ALTER TABLE public.compliance_component_implements_controls DROP CONSTRAINT IF EXISTS fk_compliance_component_implements_controls_component;

ALTER TABLE ONLY public.compliance_component_implements_controls
    ADD CONSTRAINT fk_compliance_component_implements_controls_component FOREIGN KEY (compliance_component_id) REFERENCES public.compliance_components(uuid) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS public.compliance_component_implements_control_statements (
    id uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    compliance_posture_id uuid NOT NULL,
    compliance_component_id uuid NOT NULL,
    framework_control_id text NOT NULL,
    implementation_status text NOT NULL,
    description text NOT NULL,
    CONSTRAINT uq_statement_posture_component UNIQUE (compliance_posture_id, compliance_component_id)
);

ALTER TABLE public.compliance_component_implements_control_statements DROP CONSTRAINT IF EXISTS fk_statements_posture;

ALTER TABLE ONLY public.compliance_component_implements_control_statements
    ADD CONSTRAINT fk_statements_posture FOREIGN KEY (compliance_posture_id) REFERENCES public.compliance_postures(id) ON DELETE CASCADE;

ALTER TABLE public.compliance_component_implements_control_statements DROP CONSTRAINT IF EXISTS fk_statements_implements_control;

ALTER TABLE ONLY public.compliance_component_implements_control_statements
    ADD CONSTRAINT fk_statements_implements_control FOREIGN KEY (compliance_component_id, framework_control_id) REFERENCES public.compliance_component_implements_controls(compliance_component_id, framework_control_id) ON DELETE CASCADE;
