CREATE TABLE IF NOT EXISTS public.mapped_controls (
    framework_control_id text NOT NULL,
    related_framework text NOT NULL,
    related_control_id text NOT NULL
);

ALTER TABLE ONLY public.mapped_controls
    ADD CONSTRAINT mapped_controls_pkey PRIMARY KEY (framework_control_id, related_framework, related_control_id);

ALTER TABLE ONLY public.mapped_controls
    ADD CONSTRAINT fk_mapped_controls_framework_control FOREIGN KEY (framework_control_id) REFERENCES public.frameworks_controls(framework_control_id) ON DELETE CASCADE;
