CREATE MATERIALIZED VIEW IF NOT EXISTS public.cve_ecosystem AS
SELECT DISTINCT jc.cve_id, lower(ac.ecosystem) AS ecosystem
FROM public.cve_affected_component jc
JOIN public.affected_components ac ON ac.id = jc.affected_component_id
WHERE ac.ecosystem IS NOT NULL;

-- Leading ecosystem with text_pattern_ops makes `LIKE 'git%'` a range scan
-- regardless of database collation; cve_id as the second column keeps the scan
-- index-only. UNIQUE is also what lets ImportRC refresh the view CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_ecosystem_ecosystem_cve_id
    ON public.cve_ecosystem USING btree (ecosystem text_pattern_ops, cve_id);


