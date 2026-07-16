ALTER TABLE public.pat RENAME TO access_tokens;

ALTER TABLE public.access_tokens
    ALTER COLUMN user_id DROP NOT NULL,
    ADD COLUMN org_id TEXT,
    ADD COLUMN project_id TEXT,
    ADD COLUMN asset_id TEXT,
    ADD CONSTRAINT exactly_one_owner CHECK (
        num_nonnulls(user_id, org_id, project_id, asset_id) = 1
    );