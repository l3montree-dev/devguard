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

-- Clear existing qualifiers data (purl format like "arch=amd64" is not valid JSON)
-- and change column type to jsonb
-- Convert "key1=val1&key2=val2" format to {"key1":"val1","key2":"val2"}
UPDATE public.affected_components 
SET qualifiers = (
    SELECT COALESCE(jsonb_object_agg(
        split_part(kv, '=', 1), 
        split_part(kv, '=', 2)
    ), '{}'::jsonb)
    FROM unnest(string_to_array(qualifiers, '&')) AS kv
    WHERE kv IS NOT NULL AND kv != ''
)
WHERE qualifiers IS NOT NULL AND qualifiers != '';

ALTER TABLE public.affected_components
ALTER COLUMN qualifiers TYPE jsonb USING '{}'::jsonb;
