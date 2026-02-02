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

-- Drop the CVE foreign key constraint
ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS fk_vex_rules_cve;

-- Drop composite primary key
ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS vex_rules_pkey;

-- Add back UUID primary key column
ALTER TABLE public.vex_rules ADD COLUMN id UUID DEFAULT gen_random_uuid();
ALTER TABLE public.vex_rules ADD PRIMARY KEY (id);

-- Drop the new columns
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS path_pattern_hash;
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS vex_source;
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS event_type;
