-- The vulndb list endpoint filters by ecosystem. The predicate used to be
-- `ecosystem ILIKE 'npm%'`, which no btree index can serve, so every request
-- seq scanned all 2.3M affected_components rows.
--
-- applyFilters now emits `LOWER(ecosystem) LIKE LOWER(?)` - the same predicate,
-- verified to agree with ILIKE on every row for every pattern the UI sends -
-- which this index serves as a prefix scan, including through a bind parameter.
-- text_pattern_ops is what makes `LIKE 'npm%'` indexable regardless of the
-- database collation.
CREATE INDEX IF NOT EXISTS idx_affected_components_lower_ecosystem ON public.affected_components USING btree (LOWER(ecosystem) text_pattern_ops);
