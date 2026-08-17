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

-- We can inspect upstream vex rules and scope them to a specific CVE. This allows us to do database filtering and avoid unnecessary processing of unrelated rules.
ALTER TABLE public.upstream_vex_rules ADD COLUMN cve_scope TEXT;

ALTER TABLE public.upstream_vex_rules DROP COLUMN IF EXISTS created_at;
ALTER TABLE public.upstream_vex_rules DROP COLUMN IF EXISTS updated_at;

ALTER TABLE public.vex_rules ADD COLUMN cve_scope TEXT;
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS updated_at;


CREATE INDEX IF NOT EXISTS idx_upstream_vex_rules_cve_scope ON public.upstream_vex_rules USING hash (cve_scope);


ALTER TABLE public.dependency_vulns ADD COLUMN signature TEXT NOT NULL DEFAULT '';

ALTER TABLE public.vex_rule_recommendations ADD COLUMN dependency_vuln_signature TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_dependency_vulns_signature ON public.dependency_vulns USING hash (signature);

CREATE INDEX IF NOT EXISTS idx_vex_rule_recommendations_signature ON public.vex_rule_recommendations USING hash (dependency_vuln_signature);

ALTER TABLE public.vex_rule_recommendations DROP CONSTRAINT IF EXISTS vex_rule_recommendations_pkey;

ALTER TABLE public.vex_rule_recommendations
    ADD CONSTRAINT vex_rule_recommendations_pkey PRIMARY KEY (dependency_vuln_id, dependency_vuln_signature);