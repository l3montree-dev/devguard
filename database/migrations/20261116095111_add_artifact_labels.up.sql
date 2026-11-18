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

CREATE TABLE IF NOT EXISTS public.labels (
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES public.organizations(id) ON DELETE CASCADE,
    project_id uuid REFERENCES public.projects(id) ON DELETE CASCADE,
    asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    label text,
    background_color VARCHAR(7),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() 
);

CREATE TABLE public.projects_assets_artifacts_labels (
    id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid REFERENCES public.projects(id) ON DELETE CASCADE,
    asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    artifact_id uuid REFERENCES public.artifacts(id) ON DELETE CASCADE,
    label_id uuid NOT NULL REFERENCES public.labels(id) ON DELETE CASCADE,
    CHECK (num_nonnulls(project_id, asset_id, artifact_id) = 1)
);

