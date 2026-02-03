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

-- Add enabled column to vex_rules (default true for backward compatibility)
ALTER TABLE public.vex_rules
ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true;

-- Set enabled=false for VEX rules on assets with paranoid_mode=true
-- These rules were created but their events were ignored due to paranoid mode
UPDATE public.vex_rules
SET enabled = false
WHERE asset_id IN (SELECT id FROM public.assets WHERE paranoid_mode = true);

-- Drop upstream column from vuln_events
-- This is safe because:
-- 1. New logic will not use upstream
-- 2. Existing events have already had their state effects applied
ALTER TABLE public.vuln_events
DROP COLUMN IF EXISTS upstream;
