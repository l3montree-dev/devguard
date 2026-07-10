CREATE TABLE IF NOT EXISTS public.frameworks_controls (
    framework_control_id text NOT NULL,
    framework text NOT NULL DEFAULT '',
    control_id text NOT NULL DEFAULT '',

    title text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',

    importance text DEFAULT '',

    class text NOT NULL DEFAULT '',
    additional jsonb,
    parent_framework_control_id text,

    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.frameworks_controls
    ADD CONSTRAINT frameworks_controls_pkey PRIMARY KEY (framework_control_id);

-- Ensure framework + control_id are unique
ALTER TABLE public.frameworks_controls
    ADD CONSTRAINT frameworks_controls_framework_control_id_unique UNIQUE (framework, control_id);

CREATE INDEX IF NOT EXISTS idx_frameworks_controls_parent_framework_control_id ON public.frameworks_controls (parent_framework_control_id);
