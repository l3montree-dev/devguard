
ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS cel_expression TEXT NOT NULL DEFAULT '';

ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';


UPDATE public.vex_rules SET cel_expression = format('vuln.cveId == "%s" && matchesPattern(vuln, %s)', cve_id::text, path_pattern::text);

UPDATE public.vex_rules SET title = format('VEX rule for %s', cve_id::text);

ALTER TABLE public.vex_rules DROP COLUMN path_pattern;

ALTER TABLE public.vex_rules DROP COLUMN cve_id;

ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS asset_version_name;