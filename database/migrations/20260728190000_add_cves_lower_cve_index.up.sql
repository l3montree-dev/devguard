CREATE INDEX IF NOT EXISTS idx_cves_lower_cve ON public.cves USING hash (LOWER(cve));
ANALYZE public.cves;
