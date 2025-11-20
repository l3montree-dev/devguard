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

WITH duplicates AS (
  SELECT
    id,
    created_at,
    type,
    vuln_id,
    vuln_type,
    LAG(id) OVER (ORDER BY created_at) AS prev_id,
    ROW_NUMBER() OVER (
      PARTITION BY type, vuln_id, vuln_type, justification, arbitrary_json_data
      ORDER BY created_at
    ) AS row_num
  FROM public.vuln_events
)
DELETE FROM vuln_events WHERE id IN(SELECT id FROM duplicates WHERE row_num > 1)