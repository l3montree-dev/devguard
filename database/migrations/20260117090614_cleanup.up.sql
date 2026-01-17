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
WHERE id IN (
    SELECT id FROM (
        SELECT 
            id,
            type,
            LEAD(type) OVER (
                PARTITION BY vuln_id, vuln_type 
                ORDER BY created_at ASC
            ) as next_type
        FROM public.vuln_events
    ) ranked
    WHERE type = 'rawRiskAssessmentUpdated' 
      AND next_type = 'rawRiskAssessmentUpdated'
);

DELETE FROM public.vuln_events
WHERE id IN (
    SELECT ve.id
    FROM public.vuln_events ve
    INNER JOIN (
        -- Get the last detected event per vulnerability (by timestamp, then by id for tie-breaking)
        SELECT DISTINCT ON (vuln_id, vuln_type) id as last_detected_id, vuln_id, vuln_type, created_at as last_detected_at
        FROM public.vuln_events
        WHERE type = 'detected'
        ORDER BY vuln_id, vuln_type, created_at DESC, id DESC
    ) last_detected ON ve.vuln_id = last_detected.vuln_id 
                    AND ve.vuln_type = last_detected.vuln_type
    WHERE ve.created_at < last_detected.last_detected_at
       OR (ve.created_at = last_detected.last_detected_at AND ve.id != last_detected.last_detected_id)
);