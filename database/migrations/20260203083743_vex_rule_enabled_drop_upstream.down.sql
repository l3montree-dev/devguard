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

-- Re-add upstream column with default 0 (Internal)
ALTER TABLE vuln_events
ADD COLUMN IF NOT EXISTS upstream integer NOT NULL DEFAULT 0;

-- Remove enabled column from vex_rules
ALTER TABLE vex_rules
DROP COLUMN IF EXISTS enabled;
