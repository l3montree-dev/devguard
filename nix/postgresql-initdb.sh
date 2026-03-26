#!/bin/bash
# Sourced from devguard-helm-chart/templates/postgresql/postgresql-initdb.yaml
# Processed by the docker-library entrypoint from /docker-entrypoint-initdb.d/

psql -U "${POSTGRES_USER}" <<-END
    CREATE EXTENSION IF NOT EXISTS semver;

    CREATE DATABASE kratos;
    CREATE USER kratos PASSWORD '${KRATOS_PASSWORD}';
    GRANT ALL PRIVILEGES ON DATABASE kratos to kratos;

    \c kratos

    GRANT USAGE, CREATE ON SCHEMA public TO kratos;
END
