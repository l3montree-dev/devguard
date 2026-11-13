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

-- the risk history is computed from vuln_state_intervals on read, there is no daily update to keep track of anymore
ALTER TABLE public.artifacts DROP COLUMN IF EXISTS last_history_update;
ALTER TABLE public.asset_versions DROP COLUMN IF EXISTS last_history_update;
ALTER TABLE public.assets DROP COLUMN IF EXISTS last_history_update;
