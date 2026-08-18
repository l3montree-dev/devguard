ALTER TABLE public.mapped_controls ADD COLUMN IF NOT EXISTS relationship TEXT NOT NULL DEFAULT '';

ALTER TABLE public.mapped_controls DROP CONSTRAINT IF EXISTS mapped_controls_pkey;

ALTER TABLE public.mapped_controls
    ADD CONSTRAINT mapped_controls_pkey PRIMARY KEY (framework_control_id, related_framework, related_control_id, relationship);

ALTER TABLE public.frameworks_controls ADD COLUMN IF NOT EXISTS security_level TEXT;

DELETE FROM public.mapped_controls
WHERE framework_control_id IN (
    SELECT fc.framework_control_id
    FROM public.frameworks_controls AS fc
    WHERE fc.framework = 'SCF'
);

DELETE FROM public.frameworks_controls
WHERE framework = 'SCF';