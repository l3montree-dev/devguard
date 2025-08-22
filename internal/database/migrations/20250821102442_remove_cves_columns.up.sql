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

ALTER TABLE public.cves
    DROP COLUMN IF EXISTS exploitability_score,
    DROP COLUMN IF EXISTS impact_score,
    DROP COLUMN IF EXISTS attack_vector,
    DROP COLUMN IF EXISTS attack_complexity,
    DROP COLUMN IF EXISTS privileges_required,
    DROP COLUMN IF EXISTS user_interaction,
    DROP COLUMN IF EXISTS confidentiality_impact,
    DROP COLUMN IF EXISTS integrity_impact,
    DROP COLUMN IF EXISTS availability_impact,
    DROP COLUMN IF EXISTS severity,
    DROP COLUMN IF EXISTS scope;