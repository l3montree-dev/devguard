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

-- Every scan fixed the already fixed license risks again, so their history repeats the same fixed or
-- automatic license decision event over and over. Only the first event of such a run carries information.
-- A license decision a user made after another decision is kept, it may change the license.
DELETE FROM public.vuln_events e
USING (
    SELECT id, type, user_id, justification,
           lag(type) OVER (PARTITION BY license_risk_id ORDER BY created_at, id) AS prev_type
    FROM public.vuln_events
    WHERE license_risk_id IS NOT NULL
      AND type IN ('detected', 'reopened', 'fixed', 'accepted', 'falsePositive', 'markedForTransfer', 'licenseDecision')
) s
WHERE e.id = s.id
  AND (
      (s.type = 'fixed' AND s.prev_type = 'fixed')
      OR (s.type = 'licenseDecision' AND s.prev_type = 'licenseDecision'
          AND s.user_id = 'system' AND s.justification = 'Automatically fixed by license refresh')
  );

-- Several VEX rules matching the same dependency vuln overrode each other, so every scan added an accepted or
-- false positive event of each rule again. A rule event repeating the state the vuln already had carries no information.
DELETE FROM public.vuln_events e
USING (
    SELECT id, type, vex_rule_id,
           lag(type) OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS prev_type
    FROM public.vuln_events
    WHERE dependency_vuln_id IS NOT NULL
      AND type IN ('detected', 'reopened', 'fixed', 'accepted', 'falsePositive', 'markedForTransfer')
) s
WHERE e.id = s.id
  AND s.vex_rule_id IS NOT NULL
  AND s.type IN ('accepted', 'falsePositive')
  AND s.type = s.prev_type;
