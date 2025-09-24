CREATE EXTENSION IF NOT EXISTS semver;

CREATE DATABASE kratos;
CREATE USER kratos PASSWORD 'change-me-definitely-when-not-testing';
GRANT ALL PRIVILEGES ON DATABASE kratos to kratos;

\c kratos

GRANT USAGE, CREATE ON SCHEMA public TO kratos;