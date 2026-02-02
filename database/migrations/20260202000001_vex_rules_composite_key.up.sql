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

-- Add new columns for composite primary key
ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS path_pattern_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS vex_source TEXT NOT NULL DEFAULT '';
ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'falsePositive';

-- Drop the old UUID primary key
ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS vex_rules_pkey;
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS id;

-- Create composite primary key
ALTER TABLE public.vex_rules ADD PRIMARY KEY (asset_id, cve_id, path_pattern_hash, vex_source);

-- Add foreign key constraint to CVEs table
ALTER TABLE public.vex_rules ADD CONSTRAINT fk_vex_rules_cve
    FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
