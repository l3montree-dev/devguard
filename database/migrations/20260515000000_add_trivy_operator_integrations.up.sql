CREATE TABLE trivy_operator_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    name VARCHAR(255) NOT NULL,
    cluster_id VARCHAR(255) NOT NULL,
    secret TEXT NOT NULL,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    CONSTRAINT uq_trivy_operator_cluster_org UNIQUE (cluster_id, org_id)
);
