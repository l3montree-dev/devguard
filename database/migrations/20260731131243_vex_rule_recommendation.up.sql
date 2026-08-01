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

CREATE TABLE IF NOT EXISTS public.vex_rule_recommendations (
    dependency_vuln_id UUID NOT NULL,
    vex_rule_id TEXT NOT NULL,
    upstream_vex_rule_id TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    verified_votes INT NOT NULL DEFAULT 0,
    total_votes INT NOT NULL DEFAULT 0,
    PRIMARY KEY (dependency_vuln_id, vex_rule_id, upstream_vex_rule_id),
    FOREIGN KEY (dependency_vuln_id) REFERENCES public.dependency_vulns(id) ON DELETE CASCADE,
    FOREIGN KEY (vex_rule_id) REFERENCES public.vex_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (upstream_vex_rule_id) REFERENCES public.upstream_vex_rules(id) ON DELETE CASCADE
);