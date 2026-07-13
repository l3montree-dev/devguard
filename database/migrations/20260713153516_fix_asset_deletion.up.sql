ALTER TABLE public.artifact_dependency_vulns
    DROP CONSTRAINT IF EXISTS artifact_dependency_vulns_new_dependency_vuln_id_fkey;

ALTER TABLE public.artifact_dependency_vulns
    DROP CONSTRAINT IF EXISTS artifact_dependency_vulns_dependency_vuln_id_fkey;

ALTER TABLE public.artifact_dependency_vulns
    ADD CONSTRAINT artifact_dependency_vulns_dependency_vuln_id_fkey
    FOREIGN KEY (dependency_vuln_id) REFERENCES public.dependency_vulns(id) ON DELETE CASCADE;