ALTER TABLE public.projects ADD COLUMN IF NOT EXISTS external_entity_parent_id TEXT;

--- Add indices to the join tables - foreign keys are not indexed by default ---

