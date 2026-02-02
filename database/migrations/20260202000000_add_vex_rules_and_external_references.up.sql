-- Copyright (C) 2026 l3montree GmbH
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Create vex_rules table
CREATE TABLE IF NOT EXISTS public.vex_rules (
    id TEXT PRIMARY KEY,
    asset_id UUID NOT NULL,
    asset_version_name TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    mechanical_justification TEXT,
    path_pattern JSONB NOT NULL,
    vex_source TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL DEFAULT 'falsePositive',
    created_by_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_vex_rules_asset
        FOREIGN KEY (asset_id)
        REFERENCES public.assets(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_vex_rules_cve
        FOREIGN KEY (cve_id)
        REFERENCES public.cves(cve)
        ON DELETE CASCADE,
    CONSTRAINT fk_vex_rules_asset_version
        FOREIGN KEY (asset_version_name, asset_id)
        REFERENCES public.asset_versions(name, asset_id)
        ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_vex_rule_asset ON public.vex_rules(asset_id);
CREATE INDEX IF NOT EXISTS idx_vex_rule_asset_version ON public.vex_rules(asset_id, asset_version_name);
CREATE INDEX IF NOT EXISTS idx_vex_rule_cve ON public.vex_rules(cve_id);
CREATE INDEX IF NOT EXISTS idx_vex_rules_composite ON public.vex_rules (asset_id, asset_version_name, cve_id, vex_source);

-- Drop path_pattern column from vuln_events table if it exists
ALTER TABLE public.vuln_events DROP COLUMN IF EXISTS path_pattern;

-- Create external_references table for storing VEX/SBOM external references
CREATE TABLE IF NOT EXISTS public.external_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL,
    asset_version_name TEXT NOT NULL,
    artifact_name TEXT,
    url TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_external_refs_asset 
        FOREIGN KEY (asset_id) 
        REFERENCES public.assets(id) 
        ON DELETE CASCADE,
    CONSTRAINT fk_external_refs_asset_version 
        FOREIGN KEY (asset_version_name, asset_id) 
        REFERENCES public.asset_versions(name, asset_id) 
        ON DELETE CASCADE
);

-- Create indices for common queries
CREATE INDEX IF NOT EXISTS idx_external_refs_asset_id ON public.external_references(asset_id);
CREATE INDEX IF NOT EXISTS idx_external_refs_asset_version ON public.external_references(asset_id, asset_version_name);
CREATE INDEX IF NOT EXISTS idx_external_refs_artifact ON public.external_references(artifact_name);
