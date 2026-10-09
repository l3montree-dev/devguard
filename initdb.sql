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

CREATE EXTENSION IF NOT EXISTS semver;

CREATE DATABASE kratos;
CREATE USER kratos PASSWORD 'change-me-definitely-when-not-testing-kratos';
GRANT ALL PRIVILEGES ON DATABASE kratos to kratos;

\c kratos

GRANT USAGE, CREATE ON SCHEMA public TO kratos;


CREATE DATABASE river;
CREATE USER river PASSWORD 'change-me-definitely-when-not-testing-river';
GRANT ALL PRIVILEGES ON DATABASE river to river;

\c river

GRANT USAGE, CREATE ON SCHEMA public TO river;