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

-- a CEL expression deciding which asset versions the daemon keeps. the default branch is always kept.
-- the default: tags are kept, branches are deleted 7 days after their creation or their last upload, whichever is later.
-- keep in sync with celrules.DefaultAssetVersionRetentionPolicy
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS asset_version_retention_policy text NOT NULL
    DEFAULT 'ref.type == "tag" || ref.defaultBranch || timestamp(ref.createdAt) > now() - duration("168h") || (has(ref.lastUploadAt) && timestamp(ref.lastUploadAt) > now() - duration("168h"))';

ALTER TABLE public.asset_versions ADD COLUMN IF NOT EXISTS last_upload_at TIMESTAMP WITH TIME ZONE;

-- last_accessed_at is the closest thing we have for existing asset versions - without it every
-- retention policy using lastUploadAt would fail to evaluate for them until their next scan
UPDATE public.asset_versions SET last_upload_at = last_accessed_at WHERE last_upload_at IS NULL;

ALTER TABLE public.asset_versions DROP COLUMN IF EXISTS last_accessed_at;
