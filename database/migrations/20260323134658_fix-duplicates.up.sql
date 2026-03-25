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

CREATE INDEX idx_vuln_events_dedupe
ON public.vuln_events (type, vuln_id, vuln_type, justification, id);

-- 1. Stage the duplicate IDs
CREATE TABLE public.dupes_to_delete AS
SELECT id FROM (
  SELECT id,
         ROW_NUMBER() OVER (
           PARTITION BY type, vuln_id, vuln_type, justification
           ORDER BY id
         ) AS rn
  FROM public.vuln_events
) t
WHERE rn > 1;

CREATE INDEX ON public.dupes_to_delete(id);

SELECT COUNT(*) FROM public.dupes_to_delete;

CREATE TABLE public.vuln_events_new (LIKE public.vuln_events INCLUDING ALL);

-- 2. Insert only rows NOT in dupes_to_delete
INSERT INTO public.vuln_events_new
SELECT * FROM public.vuln_events v
WHERE NOT EXISTS (
  SELECT 1 FROM public.dupes_to_delete d WHERE d.id = v.id
);

SELECT COUNT(*) FROM public.vuln_events;
SELECT COUNT(*) FROM public.vuln_events_new;
-- 4. Swap
ALTER TABLE public.vuln_events RENAME TO vuln_events_old;
ALTER TABLE public.vuln_events_new RENAME TO vuln_events;


-- 6. Verify then drop
DROP TABLE public.vuln_events_old;
DROP TABLE public.dupes_to_delete;

ANALYZE public.vuln_events;