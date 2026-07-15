CREATE TABLE IF NOT EXISTS public.mapped_controls (
    framework_control_id text PRIMARY KEY NOT NULL,
    related_framework text PRIMARY KEY NOT NULL,
    related_control_id text PRIMARY KEY NOT NULL
);

ALTER TABLE public.mapped_controls DROP CONSTRAINT IF EXISTS fk_mapped_controls_framework_control;

ALTER TABLE ONLY public.mapped_controls
    ADD CONSTRAINT fk_mapped_controls_framework_control FOREIGN KEY (framework_control_id) REFERENCES public.frameworks_controls(framework_control_id) ON DELETE CASCADE;
