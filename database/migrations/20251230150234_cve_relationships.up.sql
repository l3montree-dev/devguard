CREATE TABLE IF NOT EXISTS public.cve_relationships (
    target_cve TEXT,
    source_cve TEXT,
    relationship_type TEXT,
    PRIMARY KEY (target_cve, source_cve, relationship_type)
);
    
CREATE INDEX IF NOT EXISTS idx_cve_relationships_target_cve ON public.cve_relationships USING btree (target_cve);
