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
-- the default reproduces the former hard coded cleanup: tags are kept, branches are deleted after 7 days without a scan.
-- keep in sync with celrules.DefaultAssetVersionRetentionPolicy
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS asset_version_retention_policy text NOT NULL
    DEFAULT 'ref.type == "tag" || timestamp(ref.lastAccessedAt) > now() - duration("168h")';
