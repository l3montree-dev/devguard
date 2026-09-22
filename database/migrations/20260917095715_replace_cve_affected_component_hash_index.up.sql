-- The vulndb list endpoint preloads AffectedComponents, which GORM expands into
-- `SELECT * FROM cve_affected_component WHERE cve_id IN (...100 ids...)`. For a
-- single page that returns ~85k join rows, so the lookup is entirely I/O bound.
--
-- cve_id was served by a hash index. Two problems with that:
--   * hash stores no payload, so every match still needs a heap fetch - 461
--     random heap blocks per call on top of the index reads.
--   * on bigint it is also bigger than the btree over the same data: 673 MB,
--     more than the 708 MB table and more than the 505 MB primary key.
--
-- A btree on (cve_id, affected_component_id) covers both columns of this
-- two-column table, so the same query becomes an Index Only Scan with
-- Heap Fetches: 0 - estimated cost 64254 -> 2231. It also leads with cve_id,
-- so it serves every equality lookup the hash index did, plus ranges and
-- ordering the hash index could not.
CREATE INDEX IF NOT EXISTS idx_cve_affected_component_cve_id
    ON public.cve_affected_component USING btree (cve_id, affected_component_id);

DROP INDEX IF EXISTS public.cve_affected_component_cve_id;
