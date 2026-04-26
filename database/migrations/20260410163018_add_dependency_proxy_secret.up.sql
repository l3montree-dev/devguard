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

CREATE TABLE IF NOT EXISTS public.dependency_proxy_secrets (
    secret uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    asset_id uuid,
    project_id uuid,
    org_id uuid,
    CONSTRAINT dependency_proxy_secrets_exactly_one_scope CHECK (
        ((asset_id IS NOT NULL)::int + (project_id IS NOT NULL)::int + (org_id IS NOT NULL)::int) = 1
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS dependency_proxy_secrets_unique_asset_id
    ON public.dependency_proxy_secrets (asset_id)
    WHERE asset_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS dependency_proxy_secrets_unique_project_id
    ON public.dependency_proxy_secrets (project_id)
    WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS dependency_proxy_secrets_unique_org_id
    ON public.dependency_proxy_secrets (org_id)
    WHERE org_id IS NOT NULL;
