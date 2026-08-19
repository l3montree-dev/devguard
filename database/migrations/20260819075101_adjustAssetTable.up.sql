ALTER TABLE IF EXISTS public.assets
    ADD COLUMN modified_attack_vector text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_attack_complexity text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_privileges_required text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_scope text DEFAULT 'X'::text NOT NULL,