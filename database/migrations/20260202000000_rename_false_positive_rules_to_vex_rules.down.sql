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

-- Rename vex_rules table back to false_positive_rules
ALTER TABLE IF EXISTS public.vex_rules RENAME TO false_positive_rules;

-- Rename indexes back
ALTER INDEX IF EXISTS idx_vex_rule_asset RENAME TO idx_false_positive_rule_asset;
ALTER INDEX IF EXISTS idx_vex_rule_cve RENAME TO idx_false_positive_rule_cve;

-- Rename constraint back
ALTER TABLE IF EXISTS public.false_positive_rules
    RENAME CONSTRAINT fk_vex_rules_asset TO fk_false_positive_rules_asset;
