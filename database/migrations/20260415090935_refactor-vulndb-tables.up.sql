-- Drop unused columns from affected_components table to save memory and improve query speed
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS source;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS scheme;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS type;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS name;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS namespace;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS qualifiers;

-- Drop the dependency_vulns FK so TRUNCATE CASCADE does not destroy user data
ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;

-- Truncate all vulndb tables; CASCADE cleans up internal FKs automatically
TRUNCATE public.cves, public.affected_components, public.malicious_packages, public.malicious_affected_components CASCADE;

-- Drop primary keys so we can redefine the column types (look up actual constraint names to handle renames)
DO $$ DECLARE r record;
BEGIN
    FOR r IN SELECT constraint_name FROM information_schema.table_constraints
             WHERE table_schema = 'public' AND table_name = 'affected_components' AND constraint_type = 'PRIMARY KEY'
    LOOP EXECUTE 'ALTER TABLE public.affected_components DROP CONSTRAINT ' || quote_ident(r.constraint_name); END LOOP;
    FOR r IN SELECT constraint_name FROM information_schema.table_constraints
             WHERE table_schema = 'public' AND table_name = 'cve_affected_component' AND constraint_type = 'PRIMARY KEY'
    LOOP EXECUTE 'ALTER TABLE public.cve_affected_component DROP CONSTRAINT ' || quote_ident(r.constraint_name); END LOOP;
    FOR r IN SELECT constraint_name FROM information_schema.table_constraints
             WHERE table_schema = 'public' AND table_name = 'cves' AND constraint_type = 'PRIMARY KEY'
    LOOP EXECUTE 'ALTER TABLE public.cves DROP CONSTRAINT ' || quote_ident(r.constraint_name); END LOOP;
END $$;

-- Rebuild affected_components with bigint id
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS id;
ALTER TABLE public.affected_components ADD COLUMN id bigint;
ALTER TABLE public.affected_components ADD PRIMARY KEY (id);

-- Rebuild cve_affected_component with bigint columns
ALTER TABLE public.cve_affected_component DROP COLUMN IF EXISTS affected_component_id;
ALTER TABLE public.cve_affected_component DROP COLUMN IF EXISTS cvecve;
ALTER TABLE public.cve_affected_component DROP COLUMN IF EXISTS cve_id;
ALTER TABLE public.cve_affected_component ADD COLUMN affected_component_id bigint;
ALTER TABLE public.cve_affected_component ADD COLUMN cve_id bigint;
ALTER TABLE public.cve_affected_component ADD PRIMARY KEY (affected_component_id, cve_id);

-- Rebuild cves with bigint id as primary key, keep cve as unique key
ALTER TABLE public.cves DROP COLUMN IF EXISTS id;
ALTER TABLE public.cves ADD COLUMN id bigint;
ALTER TABLE public.cves ADD PRIMARY KEY (id);
ALTER TABLE public.cves ADD CONSTRAINT cves_cve_unique UNIQUE (cve);

-- Re-add foreign key constraints
ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_affected_component FOREIGN KEY (affected_component_id) REFERENCES public.affected_components(id) ON DELETE CASCADE;
ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_cve FOREIGN KEY (cve_id) REFERENCES public.cves(id) ON DELETE CASCADE;
ALTER TABLE public.dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
ALTER TABLE public.exploits ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
ALTER TABLE public.weaknesses ADD CONSTRAINT fk_cves_weaknesses FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
ALTER TABLE public.vex_rules ADD CONSTRAINT fk_vex_rules_cve FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
ALTER TABLE public.cve_relationships ADD CONSTRAINT fk_cve_relationships_source FOREIGN KEY (source_cve) REFERENCES public.cves(cve) ON DELETE CASCADE;

-- Drop unnecessary indexes; we add more optimized ones at the end
DROP INDEX IF EXISTS public.idx_affected_components_semver_fixed;
DROP INDEX IF EXISTS public.idx_affected_components_semver_introduced;
DROP INDEX IF EXISTS public.idx_affected_components_version_fixed;
DROP INDEX IF EXISTS public.idx_affected_components_version_introduced;
DROP INDEX IF EXISTS public.idx_affected_components_p_url;
DROP INDEX IF EXISTS public.idx_affected_components_purl_without_version;
DROP INDEX IF EXISTS public.idx_affected_components_version;

CREATE INDEX IF NOT EXISTS cve_affected_component_cve_id ON public.cve_affected_component USING hash (cve_id);

CREATE INDEX idx_affected_component_purl_version
    ON public.affected_components (purl, version);

CREATE INDEX idx_affected_component_purl_semver_range
    ON public.affected_components (purl, semver_introduced, semver_fixed)
    WHERE semver_introduced IS NOT NULL OR semver_fixed IS NOT NULL;
