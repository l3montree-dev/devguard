-- The vulndb list endpoint filters and sorts cves by date_published. Without an
-- index every such request scans the whole cves table (410 MB, dominated by the
-- description/references columns) just to reach the timestamp - even for the
-- count(*) behind the pagination header, which returns a single number.
--
-- A plain btree lets that count run as an index-only scan: 726 buffers instead
-- of 52457, ~27 ms -> ~4 ms on a warm cache, and far more on a cold one.
CREATE INDEX IF NOT EXISTS idx_cves_date_published ON public.cves USING btree (date_published);
