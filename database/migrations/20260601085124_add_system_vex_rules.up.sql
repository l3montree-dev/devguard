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

-- Create system_vex_rules table
CREATE TABLE IF NOT EXISTS public.system_vex_rules (
    id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    mechanical_justification TEXT,
    path_pattern JSONB NOT NULL,
    vex_source TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL DEFAULT 'falsePositive',
    created_by_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_system_vex_rules_cve
        FOREIGN KEY (cve_id)
        REFERENCES public.cves(cve)
        ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_vex_rule_cve ON public.system_vex_rules(cve_id);
CREATE INDEX IF NOT EXISTS idx_vex_rules_composite ON public.system_vex_rules (cve_id, vex_source);