CREATE INDEX IF NOT EXISTS idx_exploits_cve_id
    ON public.exploits USING btree (cve_id);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_components_purl
    ON public.malicious_affected_components USING btree (purl);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_components_malicious_package_id
    ON public.malicious_affected_components USING btree (malicious_package_id);

-- Primary keys cannot be dropped - they are constraints, and the tables need
-- them. Rename them out of the shadow namespace instead, so that afterwards the
-- pattern below matches nothing at all.
DO $$
DECLARE
    r RECORD;
    target TEXT;
BEGIN
    FOR r IN
        SELECT c.conname, t.relname AS tablename
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND c.conname LIKE '%shadow%'
          AND c.contype IN ('p', 'u')
    LOOP
        target := r.tablename || '_pkey';
        -- only rename when the clean name is still free
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint c2
            JOIN pg_class t2 ON t2.oid = c2.conrelid
            WHERE t2.relname = r.tablename AND c2.conname = target
        ) THEN
            EXECUTE format('ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I',
                           r.tablename, r.conname, target);
        END IF;
    END LOOP;
END $$;

-- Everything still carrying a shadow name is a redundant index: drop it.
-- Constraint-backed indexes are excluded - they were renamed above, and a
-- DROP INDEX against one would error out anyway.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT i.relname AS indexname
        FROM pg_class i
        JOIN pg_index x ON x.indexrelid = i.oid
        JOIN pg_namespace n ON n.oid = i.relnamespace
        WHERE n.nspname = 'public'
          AND i.relkind = 'i'
          AND i.relname LIKE '%shadow%'
          AND NOT EXISTS (
              SELECT 1 FROM pg_constraint c WHERE c.conindid = i.oid
          )
    LOOP
        EXECUTE format('DROP INDEX IF EXISTS public.%I', r.indexname);
    END LOOP;
END $$;
