ALTER TABLE ONLY public.assets 
    ADD COLUMN IF NOT EXISTS paranoia_mode boolean DEFAULT false NOT NULL;   

ALTER TABLE public.vuln_events
ADD COLUMN IF NOT EXISTS upstream int;    