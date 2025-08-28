-- artifact_risk_history
CREATE TABLE IF NOT EXISTS artifact_risk_history (
    artifact_name TEXT NOT NULL,
    asset_version_name TEXT NOT NULL,
    asset_id UUID NOT NULL,
    day DATE NOT NULL,
    -- Distribution
    low INT,
    high INT,
    medium INT,
    critical INT,
    low_cvss INT,
    medium_cvss INT,
    high_cvss INT,
    critical_cvss INT,
    -- History
    sum_open_risk DOUBLE PRECISION,
    avg_open_risk DOUBLE PRECISION,
    max_open_risk DOUBLE PRECISION,
    min_open_risk DOUBLE PRECISION,
    sum_closed_risk DOUBLE PRECISION,
    avg_closed_risk DOUBLE PRECISION,
    max_closed_risk DOUBLE PRECISION,
    min_closed_risk DOUBLE PRECISION,
    open_dependency_vulns INT,
    fixed_dependency_vulns INT,

    PRIMARY KEY (artifact_name, asset_version_name, asset_id, day),

    CONSTRAINT fk_artifact
        FOREIGN KEY (artifact_name, asset_version_name, asset_id)
        REFERENCES artifacts(artifact_name, asset_version_name, asset_id)
        ON DELETE CASCADE
);

ALTER TABLE public.artifacts ADD COLUMN IF NOT EXISTS last_history_update timestamp with time zone;