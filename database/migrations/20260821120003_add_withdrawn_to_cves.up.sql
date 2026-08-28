ALTER TABLE public.cves 
ADD COLUMN IF NOT EXISTS withdrawn timestamptz, 
ADD COLUMN IF NOT EXISTS cwes text;