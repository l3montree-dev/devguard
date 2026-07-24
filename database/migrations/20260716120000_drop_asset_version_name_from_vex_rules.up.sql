DROP INDEX IF EXISTS idx_vex_rule_asset_version;
DROP INDEX IF EXISTS idx_vex_rules_composite;

ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS fk_vex_rules_asset_version;
ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS asset_version_name;

CREATE INDEX IF NOT EXISTS idx_vex_rules_composite ON public.vex_rules (asset_id, cve_id, vex_source);
