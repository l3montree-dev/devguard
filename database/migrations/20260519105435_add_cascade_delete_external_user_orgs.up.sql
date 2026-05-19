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

ALTER TABLE public.external_user_orgs
    DROP CONSTRAINT IF EXISTS fk_external_user_orgs_org;

ALTER TABLE public.external_user_orgs
    ADD CONSTRAINT fk_external_user_orgs_org
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE public.external_user_orgs
    DROP CONSTRAINT IF EXISTS fk_external_user_orgs_external_user;

ALTER TABLE public.external_user_orgs
    ADD CONSTRAINT fk_external_user_orgs_external_user
        FOREIGN KEY (external_user_id) REFERENCES public.external_users(id) ON DELETE CASCADE;
