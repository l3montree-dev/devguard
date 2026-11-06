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
       
    -- 3. Drop old foreign key columns
        ALTER TABLE public.artifact_dependency_vulns DROP COLUMN artifact_artifact_name, DROP COLUMN artifact_asset_version_name,DROP COLUMN artifact_asset_id;
        ALTER TABLE public.artifact_license_risks DROP COLUMN artifact_artifact_name, DROP COLUMN artifact_asset_version_name,DROP COLUMN artifact_asset_id;
        
        ALTER TABLE public.attestations DROP COLUMN artifact_name, DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.artifact_risk_history DROP COLUMN artifact_name, DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.release_items DROP COLUMN artifact_name, DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.sboms DROP COLUMN artifact_name, DROP COLUMN asset_version_name,DROP COLUMN asset_id;

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
        ALTER TABLE public.sboms ADD PRIMARY KEY (root_subtree_hash, artifact_id,source);
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

        ALTER TABLE public.compliance_postures ADD COLUMN asset_version_id uuid;
        UPDATE public.compliance_postures child SET asset_version_id = av.id
        FROM public.asset_versions av
        WHERE av.name = child.asset_version_name AND av.asset_id = child.asset_id;
        
    -- 3. Drop the old foreign key columns
        ALTER TABLE public.advisories DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.dependency_vulns DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.supply_chain DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.first_party_vulnerabilities DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.asset_risk_history DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.in_toto_links DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.license_risks DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.artifacts DROP COLUMN asset_version_name,DROP COLUMN asset_id;
        ALTER TABLE public.compliance_postures DROP COLUMN asset_version_name,DROP COLUMN asset_id;

    -- 4. Drop the primary key, add the new primary key, add unique constraint on name+asset_id (keep semantics)
        ALTER TABLE public.asset_versions 
        DROP CONSTRAINT asset_versions_pkey,
        ADD PRIMARY KEY (id),
        ADD CONSTRAINT asset_versions_name_asset_id_unique UNIQUE (name, asset_id);

        -- Add the unique constraint in artifacts only after the asset version fkey got refactored as well
        ALTER TABLE public.artifacts
        ADD CONSTRAINT artifacts_name_asset_version_id_unique UNIQUE (artifact_name, asset_version_id);

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

    --6. Add asset_id column on important tables to avoid join
        -- Table with a few entries can be kept less optimized but more user friendly



-- HASH CALCULATION


