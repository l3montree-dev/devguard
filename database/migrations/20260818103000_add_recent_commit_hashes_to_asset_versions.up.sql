ALTER TABLE public.asset_versions
    ADD COLUMN recent_commit_hashes JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_asset_versions_recent_commit_hashes
    ON public.asset_versions USING GIN ((recent_commit_hashes -> 'recentCommits'));