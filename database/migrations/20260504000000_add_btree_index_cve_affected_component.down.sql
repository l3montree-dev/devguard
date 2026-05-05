-- Remove the btree index if rolling back
DROP INDEX IF EXISTS idx_cve_affected_component_cve_id_aff_comp_id;
