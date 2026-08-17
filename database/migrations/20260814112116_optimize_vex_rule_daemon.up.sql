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


ALTER TABLE public.dependency_vulns ADD COLUMN signature BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.dependency_vulns ADD COLUMN asset_signature BIGINT NOT NULL DEFAULT 0;

ALTER TABLE public.vex_rule_recommendations ADD COLUMN dependency_vuln_signature BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_dependency_vulns_signature ON public.dependency_vulns (signature);

CREATE INDEX IF NOT EXISTS idx_dependency_vulns_asset_signature ON public.dependency_vulns (asset_signature);

CREATE INDEX IF NOT EXISTS idx_vex_rule_recommendations_signature ON public.vex_rule_recommendations (dependency_vuln_signature);

ALTER TABLE public.vex_rule_recommendations DROP CONSTRAINT IF EXISTS vex_rule_recommendations_pkey;

ALTER TABLE public.vex_rule_recommendations
    ADD CONSTRAINT vex_rule_recommendations_pkey PRIMARY KEY (dependency_vuln_id, dependency_vuln_signature);

ALTER TABLE public.vuln_events
    ALTER COLUMN dependency_vuln_id DROP NOT NULL;

ALTER TABLE public.vuln_events
    ADD COLUMN asset_signature BIGINT;

CREATE INDEX IF NOT EXISTS idx_vuln_events_asset_signature ON public.vuln_events (asset_signature);

-- The check constraint tying dependency_vuln_id/asset_signature together is added in the
-- hash_migration.go Go migration instead of here: existing installations already have millions
-- of vuln_events rows for license risks/first-party vulns/compliance postures where both of these
-- columns are legitimately NULL, so the constraint must account for those columns too. Adding it
-- as a plain schema migration would fail against that existing data.
