    ALTER TABLE public.mapped_controls ADD COLUMN IF NOT EXISTS relationship TEXT NOT NULL DEFAULT '';

    ALTER TABLE public.mapped_controls DROP CONSTRAINT IF EXISTS mapped_controls_pkey;

    ALTER TABLE public.mapped_controls
        ADD CONSTRAINT mapped_controls_pkey PRIMARY KEY (framework_control_id, related_framework, related_control_id, relationship);
