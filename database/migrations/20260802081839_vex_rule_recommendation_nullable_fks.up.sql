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


ALTER TABLE public.vex_rule_recommendations DROP CONSTRAINT IF EXISTS vex_rule_recommendations_pkey;

ALTER TABLE public.vex_rule_recommendations ALTER COLUMN vex_rule_id DROP NOT NULL;
ALTER TABLE public.vex_rule_recommendations ALTER COLUMN upstream_vex_rule_id DROP NOT NULL;


UPDATE public.vex_rule_recommendations SET vex_rule_id = NULL WHERE vex_rule_id = '';
UPDATE public.vex_rule_recommendations SET upstream_vex_rule_id = NULL WHERE upstream_vex_rule_id = '';

ALTER TABLE public.vex_rule_recommendations ADD PRIMARY KEY (dependency_vuln_id);