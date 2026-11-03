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

-- recommendations fetched from the central VEX exchange server
CREATE TABLE IF NOT EXISTS public.vex_exchange_rules (
    id TEXT PRIMARY KEY,
    vex_source TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    justification TEXT NOT NULL,
    mechanical_justification TEXT,
    event_type TEXT NOT NULL,
    cel_expression TEXT NOT NULL,
    cve_scope TEXT,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vex_exchange_rules_cve_scope ON public.vex_exchange_rules (cve_scope);
