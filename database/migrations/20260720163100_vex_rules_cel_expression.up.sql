
ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS cel_expression TEXT NOT NULL DEFAULT '';

ALTER TABLE public.vex_rules ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';

ALTER TABLE public.vex_rules DROP COLUMN IF EXISTS cve_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'vex_rules'
          AND column_name = 'path_pattern'
    ) THEN
        UPDATE public.vex_rules
        SET cel_expression = format('matchesPattern(vuln, %s)', path_pattern::text)
        WHERE cel_expression = '';

        ALTER TABLE public.vex_rules
        DROP COLUMN path_pattern;
    END IF;
END $$;