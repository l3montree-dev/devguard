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


DELETE FROM public.vuln_events
WHERE user_id = 'system'
  AND type IN ('fixed', 'reopened');

UPDATE public.dependency_vulns dv
SET state = CASE last_event.type WHEN 'reopened' THEN 'open' WHEN 'detected' THEN 'open' ELSE last_event.type END
FROM (
    SELECT DISTINCT ON (dependency_vuln_id) dependency_vuln_id, type
    FROM public.vuln_events
    WHERE deleted_at IS NULL
    ORDER BY dependency_vuln_id, created_at DESC
) AS last_event
WHERE dv.id = last_event.dependency_vuln_id
  AND last_event.type IN ('falsePositive', 'accepted', 'reopened', 'fixed', 'detected');

