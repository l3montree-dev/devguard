ALTER TABLE public.pat RENAME TO access_tokens;

ALTER TABLE public.access_tokens
    ALTER COLUMN user_id DROP NOT NULL,
    ADD COLUMN org_id     uuid REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN project_id uuid REFERENCES projects(id)      ON DELETE CASCADE,
    ADD COLUMN asset_id   uuid REFERENCES assets(id)        ON DELETE CASCADE,
    ADD CONSTRAINT exactly_one_owner CHECK (
        num_nonnulls(user_id, org_id, project_id, asset_id) = 1
    );
