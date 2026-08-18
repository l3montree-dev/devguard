CREATE TABLE IF NOT EXISTS public.mapped_controls (
    framework_control_id text NOT NULL,
    related_framework text NOT NULL,
    related_control_id text NOT NULL,
    PRIMARY KEY (framework_control_id, related_framework, related_control_id)
);