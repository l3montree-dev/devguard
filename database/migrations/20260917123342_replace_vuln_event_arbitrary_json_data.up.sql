ALTER TABLE public.vuln_events ADD COLUMN IF NOT EXISTS risk double precision;
ALTER TABLE public.vuln_events ADD COLUMN IF NOT EXISTS compliance_component_id uuid;

-- first party vulns and license risks never had a real risk, only a zero placeholder
UPDATE public.vuln_events
SET risk = CASE
    WHEN jsonb_typeof(NULLIF(arbitrary_json_data, '')::jsonb -> 'risk') = 'number'
    THEN (NULLIF(arbitrary_json_data, '')::jsonb ->> 'risk')::double precision
END
WHERE type IN ('detected', 'rawRiskAssessmentUpdated')
    AND dependency_vuln_id IS NOT NULL;

-- older events only know the component title
UPDATE public.vuln_events ve
SET compliance_component_id = cc.uuid
FROM public.compliance_components cc
WHERE ve.type IN ('attachedComplianceComponent', 'removedComplianceComponent')
    AND cc.title = NULLIF(ve.arbitrary_json_data, '')::jsonb ->> 'componentTitle';

ALTER TABLE public.vuln_events DROP COLUMN arbitrary_json_data;

ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS fk_vuln_events_compliance_component;

ALTER TABLE ONLY public.vuln_events
    ADD CONSTRAINT fk_vuln_events_compliance_component FOREIGN KEY (compliance_component_id) REFERENCES public.compliance_components(uuid) ON DELETE SET NULL;