-- Add B-tree index to speed ordered aggregation for integrity checks
CREATE INDEX IF NOT EXISTS idx_cve_affected_component_cve_id_aff_comp_id
ON public.cve_affected_component USING BTREE (cve_id, affected_component_id);
