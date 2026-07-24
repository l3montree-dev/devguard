ALTER TABLE public.vuln_events
    ADD COLUMN IF NOT EXISTS vex_rule_id TEXT;

ALTER TABLE public.vuln_events
    DROP CONSTRAINT IF EXISTS vuln_events_vex_rule_id_fkey;

