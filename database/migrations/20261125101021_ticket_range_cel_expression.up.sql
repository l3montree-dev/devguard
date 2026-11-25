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

ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS ticket_range_cel_expression text;

UPDATE public.assets
SET ticket_range_cel_expression = 'vuln.ref.defaultBranch == true && (' || concat_ws(' || ',
    CASE WHEN cvss_automatic_ticket_threshold IS NOT NULL
        THEN '(vuln.cve != null && vuln.cve.cvss >= ' || trim_scale(cvss_automatic_ticket_threshold)::text || ')'
    END,
    CASE WHEN risk_automatic_ticket_threshold IS NOT NULL
        THEN '(vuln.riskAssessment != null && vuln.riskAssessment >= ' || trim_scale(risk_automatic_ticket_threshold)::text || ')'
    END
) || ')'
WHERE ticket_range_cel_expression IS NULL
    AND (cvss_automatic_ticket_threshold IS NOT NULL OR risk_automatic_ticket_threshold IS NOT NULL);

ALTER TABLE public.assets DROP COLUMN IF EXISTS cvss_automatic_ticket_threshold;
ALTER TABLE public.assets DROP COLUMN IF EXISTS risk_automatic_ticket_threshold;
