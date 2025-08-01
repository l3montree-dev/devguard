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

ALTER TABLE first_party_vulnerabilities
ADD COLUMN snippet_contents JSONB;

UPDATE first_party_vulnerabilities
SET snippet_contents = jsonb_build_object(
    'snippets', jsonb_build_array(
        jsonb_build_object(
            'startLine', start_line,
            'endLine', end_line,
            'startColumn', start_column,
            'endColumn', end_column,
            'snippet', snippet
        )
    )
);