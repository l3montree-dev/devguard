-- Remove the path_pattern column from vuln_events table
DROP INDEX IF EXISTS idx_vuln_events_path_pattern;
ALTER TABLE public.vuln_events DROP COLUMN IF EXISTS path_pattern;
