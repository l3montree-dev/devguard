CREATE TABLE IF NOT EXISTS public.logs (
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid,
    project_id uuid,
    asset_id uuid,
    asset_version_name text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    log_level text,
    message text
);
