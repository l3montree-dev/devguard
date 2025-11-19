ALTER TABLE ONLY public.assets 
    ADD COLUMN IF NOT EXISTS paranoid_mode boolean DEFAULT false NOT NULL;   

ALTER TABLE public.vuln_events
ADD COLUMN IF NOT EXISTS upstream integer NOT NULL DEFAULT 0;