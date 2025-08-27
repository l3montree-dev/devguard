-- Copyright (C) 2025 l3montree GmbH
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


-- releases
CREATE TABLE IF NOT EXISTS releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE
);


-- release_items
CREATE TABLE IF NOT EXISTS release_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    release_id UUID NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    child_release_id UUID REFERENCES releases(id) ON DELETE CASCADE,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    -- composite foreign key to artifacts
    artifact_name TEXT,
    asset_id UUID,
    asset_version_name TEXT,
    CONSTRAINT fk_release
        FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
    CONSTRAINT fk_child_release
        FOREIGN KEY (child_release_id) REFERENCES releases(id) ON DELETE CASCADE,
    CONSTRAINT fk_artifact
        FOREIGN KEY (artifact_name, asset_id, asset_version_name)
        REFERENCES artifacts(artifact_name, asset_id, asset_version_name)
        ON DELETE CASCADE
);

-- drop old constraint if it exists
ALTER TABLE release_items
    DROP CONSTRAINT IF EXISTS chk_one_not_null;

-- add check constraint (only one of artifact_id or child_release_id must be set)
ALTER TABLE release_items
    ADD CONSTRAINT chk_one_not_null
    CHECK (
        (child_release_id IS NOT NULL AND artifact_name IS NULL AND asset_id IS NULL AND asset_version_name IS NULL)
        OR (child_release_id IS NULL AND artifact_name IS NOT NULL AND asset_id IS NOT NULL AND asset_version_name IS NOT NULL)
    );


