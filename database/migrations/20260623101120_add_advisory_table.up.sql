CREATE TABLE public.advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT,
    vector_string TEXT,
    asset_id UUID
);

CREATE TABLE public.affected_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ecosystem TEXT NOT NULL,
    package_name TEXT,
    semver_introduced public.semver,
    semver_fixed public.semver
);

CREATE TABLE public.advisories_affected_packages (
    advisory_id UUID NOT NULL REFERENCES public.advisories(id) ON DELETE CASCADE,
    affected_package_id UUID NOT NULL REFERENCES public.affected_packages(id) ON DELETE CASCADE,
    CONSTRAINT advisories_affected_packages_pkey PRIMARY KEY (advisory_id, affected_package_id)
);

