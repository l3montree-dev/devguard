CREATE DATABASE kratos;
CREATE USER kratos PASSWORD 'secret';
GRANT ALL PRIVILEGES ON DATABASE kratos to kratos;

\c kratos

GRANT USAGE, CREATE ON SCHEMA public TO kratos;
