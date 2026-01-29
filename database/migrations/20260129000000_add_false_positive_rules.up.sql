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

-- Create false_positive_rules table
CREATE TABLE IF NOT EXISTS public.false_positive_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL,
    cve_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    mechanical_justification TEXT,
    path_pattern JSONB NOT NULL,
    created_by_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_false_positive_rules_asset
        FOREIGN KEY (asset_id)
        REFERENCES public.assets(id)
        ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_false_positive_rule_asset ON public.false_positive_rules(asset_id);
CREATE INDEX IF NOT EXISTS idx_false_positive_rule_cve ON public.false_positive_rules(cve_id);

-- Drop path_pattern column from vuln_events table
ALTER TABLE public.vuln_events DROP COLUMN IF EXISTS path_pattern;
