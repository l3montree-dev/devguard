-- Add path_pattern column to vuln_events table
-- This column stores a JSONB array representing a path suffix pattern.
-- When a false positive event has a path_pattern, it acts as a rule that
-- applies to all vulnerabilities whose path ends with this pattern.
ALTER TABLE public.vuln_events ADD COLUMN IF NOT EXISTS path_pattern JSONB DEFAULT NULL;

-- Create an index for efficient querying of events with path patterns
-- This helps when looking up rules that might apply to a vulnerability
CREATE INDEX IF NOT EXISTS idx_vuln_events_path_pattern ON public.vuln_events USING GIN (path_pattern) WHERE path_pattern IS NOT NULL;