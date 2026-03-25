CREATE INDEX IF NOT EXISTS idx_vuln_events_vuln_id ON public.vuln_events USING hash (vuln_id);
