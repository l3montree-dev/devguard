-- Create malicious_packages table
CREATE TABLE IF NOT EXISTS public.malicious_packages (
    id VARCHAR(255) PRIMARY KEY,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,
    published TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create malicious_affected_components table (similar to affected_components)
CREATE TABLE IF NOT EXISTS public.malicious_affected_components (
    id TEXT PRIMARY KEY,
    malicious_package_id VARCHAR(255) NOT NULL REFERENCES public.malicious_packages(id) ON UPDATE CASCADE ON DELETE CASCADE,
    purl TEXT NOT NULL,
    ecosystem TEXT,
    scheme TEXT,
    type TEXT,
    name TEXT,
    namespace TEXT,
    qualifiers TEXT,
    subpath TEXT,
    version TEXT,
    semver_introduced public.semver,
    semver_fixed public.semver,
    version_introduced TEXT,
    version_fixed TEXT
);

-- Create indexes for fast purl matching (similar to affected_components)
CREATE INDEX IF NOT EXISTS idx_malicious_affected_purl ON public.malicious_affected_components (purl);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_version ON public.malicious_affected_components (version);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_semver_introduced ON public.malicious_affected_components (semver_introduced);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_semver_fixed ON public.malicious_affected_components (semver_fixed);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_version_introduced ON public.malicious_affected_components (version_introduced);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_version_fixed ON public.malicious_affected_components (version_fixed);
CREATE INDEX IF NOT EXISTS idx_malicious_affected_package_id ON public.malicious_affected_components (malicious_package_id);

-- Add comments to tables
COMMENT ON TABLE public.malicious_packages IS 'Stores malicious package metadata from OSSF malicious-packages repository';
COMMENT ON TABLE public.malicious_affected_components IS 'Stores affected component information for malicious packages, allowing purl-based matching';

