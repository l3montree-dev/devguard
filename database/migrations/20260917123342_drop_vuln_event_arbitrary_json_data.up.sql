ALTER TABLE public.vuln_events DROP COLUMN arbitrary_json_data;

-- the space is reclaimed by VACUUM FULL in the post migration operations, it cannot run inside the migration transaction