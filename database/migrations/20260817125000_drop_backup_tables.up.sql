-- Copyright (C) 2026 l3montree GmbH
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.


-- Some backup tables reference other backup tables via foreign keys (e.g. a
-- "*_backup_ts" snapshot of a join table pointing at a "*_backup_ts" snapshot
-- of the table it joins). No live (non-backup) table has an FK into a backup
-- table, so there's nothing to repoint - drop those backup-to-backup
-- constraints first so the tables themselves can be dropped afterwards.
DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT con.conname, src.relname AS source_table
        FROM pg_constraint con
        JOIN pg_class src ON src.oid = con.conrelid
        JOIN pg_class tgt ON tgt.oid = con.confrelid
        WHERE con.contype = 'f'
        AND src.relname ~ '_backup_[0-9]+$'
        AND tgt.relname ~ '_backup_[0-9]+$'
    LOOP
        EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', fk.source_table, fk.conname);
    END LOOP;
END $$;

DO $$
DECLARE
    backup_table text;
BEGIN
    FOR backup_table IN
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
        AND tablename ~ '_backup_[0-9]+$'
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS public.%I', backup_table);
    END LOOP;
END $$;