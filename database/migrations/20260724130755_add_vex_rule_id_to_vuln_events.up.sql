ALTER TABLE public.vuln_events
    ADD COLUMN IF NOT EXISTS vex_rule_id TEXT;

ALTER TABLE public.vuln_events
    DROP CONSTRAINT IF EXISTS vuln_events_vex_rule_id_fkey;

ALTER TABLE public.vuln_events
    ADD CONSTRAINT vuln_events_vex_rule_id_fkey
    FOREIGN KEY (vex_rule_id) REFERENCES public.vex_rules(id)
    ON DELETE SET NULL;
