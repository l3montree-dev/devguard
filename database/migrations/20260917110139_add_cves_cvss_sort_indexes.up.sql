-- Two indexes, because the two sort directions shared/context_utils.go emits are
-- `cvss asc` and `cvss desc NULLS LAST`. cvss is nullable, so a backward scan of the
-- ascending index yields DESC NULLS FIRST and postgres will not use it for the
-- descending sort - it falls back to the full sort. The opclass has to match.
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON public.cves USING btree (cvss);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_desc ON public.cves USING btree (cvss DESC NULLS LAST);
