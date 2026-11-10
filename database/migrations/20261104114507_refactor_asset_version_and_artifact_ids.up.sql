-- Artifact Migrations
    -- 1. Add new id column type uuid and random gen each value
        ALTER TABLE public.artifacts ADD COLUMN id uuid DEFAULT gen_random_uuid();

    -- 2. Add new foreign key column to child tables and fill with respective values
        --artifact_dependency_vulns
        ALTER TABLE public.artifact_dependency_vulns ADD COLUMN artifact_id uuid;
        UPDATE public.artifact_dependency_vulns child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_artifact_name
        AND a.asset_version_name = child.artifact_asset_version_name
        AND a.asset_id = child.artifact_asset_id;

        --artifact_license_risks
        ALTER TABLE public.artifact_license_risks ADD COLUMN artifact_id uuid;
        UPDATE public.artifact_license_risks child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_artifact_name
        AND a.asset_version_name = child.artifact_asset_version_name
        AND a.asset_id = child.artifact_asset_id;

        --attestations
        ALTER TABLE public.attestations ADD COLUMN artifact_id uuid;
        UPDATE public.attestations child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_name
        AND a.asset_version_name = child.asset_version_name
        AND a.asset_id = child.asset_id;

        --artifact_risk_history
        ALTER TABLE public.artifact_risk_history ADD COLUMN artifact_id uuid;
        UPDATE public.artifact_risk_history child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_name
        AND a.asset_version_name = child.asset_version_name
        AND a.asset_id = child.asset_id;

        --release_items
        ALTER TABLE public.release_items ADD COLUMN artifact_id uuid;
        UPDATE public.release_items child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_name
        AND a.asset_version_name = child.asset_version_name
        AND a.asset_id = child.asset_id;

        -- sboms
        ALTER TABLE public.sboms ADD COLUMN artifact_id uuid;
        UPDATE public.sboms child SET artifact_id = a.id
        FROM public.artifacts a
        WHERE a.artifact_name = child.artifact_name
        AND a.asset_version_name = child.asset_version_name
        AND a.asset_id = child.asset_id;

    -- 3. Drop old foreign key columns, asset_id is kept as denormalized column to avoid joins
        ALTER TABLE public.artifact_dependency_vulns DROP COLUMN artifact_artifact_name, DROP COLUMN artifact_asset_version_name,DROP COLUMN artifact_asset_id;
        ALTER TABLE public.artifact_license_risks DROP COLUMN artifact_artifact_name, DROP COLUMN artifact_asset_version_name,DROP COLUMN artifact_asset_id;

        ALTER TABLE public.attestations DROP COLUMN artifact_name, DROP COLUMN asset_version_name;
        ALTER TABLE public.artifact_risk_history DROP COLUMN artifact_name, DROP COLUMN asset_version_name;
        ALTER TABLE public.release_items DROP COLUMN artifact_name, DROP COLUMN asset_version_name;
        ALTER TABLE public.sboms DROP COLUMN artifact_name, DROP COLUMN asset_version_name;

    -- 4. Drop the primary key, add the new primary key
        ALTER TABLE public.artifacts
        DROP CONSTRAINT artifacts_pkey,
        ADD PRIMARY KEY (id);

    -- 5. Add the new foreign keys
        ALTER TABLE public.release_items ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;
        ALTER TABLE public.artifact_risk_history ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;
        ALTER TABLE public.attestations ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;
        ALTER TABLE public.artifact_license_risks ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;
        ALTER TABLE public.artifact_dependency_vulns ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;
        ALTER TABLE public.sboms ADD FOREIGN KEY (artifact_id) REFERENCES public.artifacts (id) ON DELETE CASCADE;

    -- 6. Update the primary keys where we dropped included artifact columns
        ALTER TABLE public.artifact_dependency_vulns ADD PRIMARY KEY (artifact_id, dependency_vuln_id);
        ALTER TABLE public.artifact_license_risks ADD PRIMARY KEY (artifact_id, license_risk_id);
        ALTER TABLE public.artifact_risk_history ADD PRIMARY KEY (artifact_id, day);
        -- one sbom per artifact and source like before, root_subtree_hash lookups have their own index
        ALTER TABLE public.sboms ADD PRIMARY KEY (artifact_id, source);
        ALTER TABLE public.attestations ADD PRIMARY KEY (artifact_id, predicate_type);

-- Asset Versions Migration
    -- 1. Add new id column type uuid and random gen each value
        ALTER TABLE public.asset_versions ADD COLUMN id uuid DEFAULT gen_random_uuid();

    -- 2. Add new foreign key column to child tables and fill with respective values
        ALTER TABLE public.advisories ADD COLUMN asset_version_id uuid;
        UPDATE public.advisories child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.dependency_vulns ADD COLUMN asset_version_id uuid;
        UPDATE public.dependency_vulns child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.supply_chain ADD COLUMN asset_version_id uuid;
        UPDATE public.supply_chain child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.first_party_vulnerabilities ADD COLUMN asset_version_id uuid;
        UPDATE public.first_party_vulnerabilities child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.in_toto_links ADD COLUMN asset_version_id uuid;
        UPDATE public.in_toto_links child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.license_risks ADD COLUMN asset_version_id uuid;
        UPDATE public.license_risks child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.artifacts ADD COLUMN asset_version_id uuid;
        UPDATE public.artifacts child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

        ALTER TABLE public.asset_risk_history ADD COLUMN asset_version_id uuid;
        UPDATE public.asset_risk_history child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;
        -- the old table had no foreign key, so history of deleted asset versions is still around and can not be mapped
        DELETE FROM public.asset_risk_history WHERE asset_version_id IS NULL;

        ALTER TABLE public.compliance_postures ADD COLUMN asset_version_id uuid;
        UPDATE public.compliance_postures child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;

    -- 3. Drop the old foreign key columns, asset_id is kept as denormalized column to avoid joins
        -- asset_version_name is kept on dependency_vulns, first_party_vulnerabilities, license_risks and compliance_postures since it is part of their content hash
        ALTER TABLE public.advisories DROP COLUMN asset_version_name;
        ALTER TABLE public.supply_chain DROP COLUMN asset_version_name;
        ALTER TABLE public.asset_risk_history DROP COLUMN asset_version_name;
        ALTER TABLE public.in_toto_links DROP COLUMN asset_version_name;
        ALTER TABLE public.artifacts DROP COLUMN asset_version_name;

    -- 4. Drop the primary key, add the new primary key, add unique constraint on asset_id+name (keep semantics)
        -- CASCADE drops the remaining (name, asset_id) foreign keys of the hash tables and legacy tables
        -- the parent id leads the unique constraints, so they also index listing the children of a parent
        ALTER TABLE public.asset_versions
        DROP CONSTRAINT asset_versions_pkey CASCADE,
        ADD PRIMARY KEY (id),
        ADD CONSTRAINT asset_versions_asset_id_name_unique UNIQUE (asset_id, name);

        -- Add the unique constraint in artifacts only after the asset version fkey got refactored as well
        ALTER TABLE public.artifacts
        ADD CONSTRAINT artifacts_asset_version_id_artifact_name_unique UNIQUE (asset_version_id, artifact_name);

    -- 5. Add the new foreign keys pointing at the asset version id column
        ALTER TABLE public.artifacts ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.license_risks ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.in_toto_links ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.first_party_vulnerabilities ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.supply_chain ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.dependency_vulns ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.advisories ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.asset_risk_history ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;
        ALTER TABLE public.compliance_postures ADD FOREIGN KEY (asset_version_id) REFERENCES public.asset_versions (id) ON DELETE CASCADE;

    -- 6. Update the primary keys where we dropped included asset_version columns
        ALTER TABLE public.in_toto_links ADD PRIMARY KEY (supply_chain_id, step, asset_version_id);
        ALTER TABLE public.asset_risk_history ADD PRIMARY KEY (asset_version_id, day);

    -- 7. These always belong to an asset version, compliance postures, advisories and supply chains stay nullable
        ALTER TABLE public.artifacts ALTER COLUMN asset_version_id SET NOT NULL;
        ALTER TABLE public.dependency_vulns ALTER COLUMN asset_version_id SET NOT NULL;
        ALTER TABLE public.first_party_vulnerabilities ALTER COLUMN asset_version_id SET NOT NULL;
        ALTER TABLE public.license_risks ALTER COLUMN asset_version_id SET NOT NULL;

-- Indexes
    -- 1. The name based indexes on the kept hash columns are not used by any query anymore
        DROP INDEX IF EXISTS public.idx_dependency_vulns_asset_lookup;
        DROP INDEX IF EXISTS public.idx_dependency_vulns_asset_version_state;
        DROP INDEX IF EXISTS public.idx_license_risks_asset_lookup;
        DROP INDEX IF EXISTS public.idx_first_party_vulnerabilities_asset_version_name_asset_id;
        DROP INDEX IF EXISTS public.idx_compliance_postures_asset_lookup;

    -- 2. Replace every name based index with its id equivalent, which also covers the foreign key cascades
        CREATE INDEX IF NOT EXISTS idx_dependency_vulns_asset_version_state ON public.dependency_vulns USING btree (asset_version_id, state);
        CREATE INDEX IF NOT EXISTS idx_license_risks_asset_version_id ON public.license_risks USING hash (asset_version_id);
        CREATE INDEX IF NOT EXISTS idx_first_party_vulnerabilities_asset_version_id ON public.first_party_vulnerabilities USING hash (asset_version_id);
        CREATE INDEX IF NOT EXISTS idx_compliance_postures_asset_version_id ON public.compliance_postures USING hash (asset_version_id);
        CREATE INDEX IF NOT EXISTS idx_advisories_asset_version_id ON public.advisories USING hash (asset_version_id);
        CREATE INDEX IF NOT EXISTS idx_supply_chain_asset_version_id ON public.supply_chain USING hash (asset_version_id);
        CREATE INDEX IF NOT EXISTS idx_release_items_artifact_id ON public.release_items USING hash (artifact_id);

    -- 3. Asset wide lookups were served by the asset_id prefix of the dropped name based indexes
        CREATE INDEX IF NOT EXISTS idx_license_risks_asset_id ON public.license_risks USING hash (asset_id);
        CREATE INDEX IF NOT EXISTS idx_advisories_asset_id ON public.advisories USING hash (asset_id);
        CREATE INDEX IF NOT EXISTS idx_artifact_risk_history_asset_day ON public.artifact_risk_history USING btree (asset_id, day);

-- VACUUM ANALYZE of the rewritten tables cannot run inside the migration transaction, it runs as post migration statement in database/migrations.go
