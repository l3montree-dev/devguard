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

-- Fix 1: Add CASCADE to license_risks.component_purl foreign key
-- This constraint was added without CASCADE in migration 20250822131113
ALTER TABLE public.component_dependencies
DROP CONSTRAINT IF EXISTS fk_component_dependencies_asset_version;

-- Fix 2: Add foreign key for component_dependencies.asset_version
-- This relationship was missing a foreign key constraint entirely
ALTER TABLE public.component_dependencies
ADD CONSTRAINT fk_component_dependencies_asset_version
FOREIGN KEY (asset_version_name, asset_id)
REFERENCES public.asset_versions(name, asset_id)
ON DELETE CASCADE
ON UPDATE CASCADE;

-- Fix 3: Add CASCADE to assets.project_id foreign key
-- Check if constraint exists first, then recreate with CASCADE
ALTER TABLE public.assets DROP CONSTRAINT IF EXISTS fk_assets_project;

ALTER TABLE public.assets
ADD CONSTRAINT fk_assets_project
FOREIGN KEY (project_id)
REFERENCES public.projects(id)
ON DELETE CASCADE
ON UPDATE CASCADE;

-- Fix 4: Add CASCADE to supply_chain.asset_version foreign key if needed
-- Check if the constraint exists and has proper CASCADE
ALTER TABLE public.supply_chain
DROP CONSTRAINT IF EXISTS fk_supply_chain_asset_version;

ALTER TABLE public.supply_chain
ADD CONSTRAINT fk_supply_chain_asset_version
FOREIGN KEY (asset_version_name, asset_id)
REFERENCES public.asset_versions(name, asset_id)
ON DELETE CASCADE
ON UPDATE CASCADE;