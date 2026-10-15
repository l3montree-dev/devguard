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

-- the auto reopen setting is replaced by a reopen vex rule - those are evaluated against accepted vulns.
-- the id matches models.CalculateVEXRuleID, values <= 0 disabled the setting.
INSERT INTO public.vex_rules (id, asset_id, title, justification, vex_source, event_type, created_by_id, cel_expression)
SELECT encode(sha256(convert_to(id || '/' || cel_expression || '/manual', 'UTF8')), 'hex'),
       id,
       format('Reopen vulnerabilities accepted for more than %s days', days),
       format('Automatically reopened since the vulnerability was accepted more than %s days ago', days),
       'manual',
       'reopened',
       'system',
       cel_expression
FROM (
    SELECT id, vuln_auto_reopen_after_days AS days,
           format('now() - timestamp(vuln.lastStateChange) > duration("%sh")', vuln_auto_reopen_after_days * 24) AS cel_expression
    FROM public.assets
    WHERE vuln_auto_reopen_after_days > 0
) assets
ON CONFLICT (id) DO NOTHING;

-- the asset pipeline steps are river jobs now, their finished jobs track when a step ran last
ALTER TABLE public.assets
    DROP COLUMN IF EXISTS pipeline_last_run,
    DROP COLUMN IF EXISTS pipeline_error,
    DROP COLUMN IF EXISTS vuln_auto_reopen_after_days;
