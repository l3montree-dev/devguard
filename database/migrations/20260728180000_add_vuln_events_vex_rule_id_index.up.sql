CREATE INDEX IF NOT EXISTS idx_vuln_events_vex_rule_id ON public.vuln_events USING hash (vex_rule_id);
