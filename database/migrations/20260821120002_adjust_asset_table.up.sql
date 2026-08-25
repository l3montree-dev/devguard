ALTER TABLE IF EXISTS public.assets
    ADD COLUMN modified_attack_vector text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_attack_complexity text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_privileges_required text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_scope text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_user_interaction text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_confidentiality text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_integrity text DEFAULT 'X'::text NOT NULL,
    ADD COLUMN modified_availability text DEFAULT 'X'::text NOT NULL,
    DROP COLUMN reachable_from_internet;