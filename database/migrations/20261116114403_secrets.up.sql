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

CREATE TABLE IF NOT EXISTS public.secrets (
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    org_id     uuid REFERENCES public.organizations(id) ON DELETE CASCADE,
    project_id uuid REFERENCES public.projects(id)      ON DELETE CASCADE,
    asset_id   uuid REFERENCES public.assets(id)        ON DELETE CASCADE,
    CONSTRAINT exactly_one_owner CHECK (
        num_nonnulls(org_id, project_id, asset_id) = 1
    ),
    CONSTRAINT secrets_name_format CHECK (name ~ '^[a-z0-9_]+$')
);
CREATE UNIQUE INDEX IF NOT EXISTS secrets_unique_org_id_name
    ON public.secrets (org_id, name)
    WHERE org_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_unique_project_id_name
    ON public.secrets (project_id, name)
    WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS secrets_unique_asset_id_name
    ON public.secrets (asset_id, name)
    WHERE asset_id IS NOT NULL;
