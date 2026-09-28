CREATE INDEX IF NOT EXISTS idx_vuln_events_compliance_posture_id ON public.vuln_events USING btree (compliance_posture_id) WHERE compliance_posture_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vuln_events_security_advisory_id ON public.vuln_events USING btree (security_advisory_id) WHERE security_advisory_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_compliance_postures_asset_lookup ON public.compliance_postures USING btree (asset_id, asset_version_name);
CREATE INDEX IF NOT EXISTS idx_advisories_asset_lookup ON public.advisories USING btree (asset_id, asset_version_name);

CREATE INDEX IF NOT EXISTS idx_artifact_risk_history_asset_version_day ON public.artifact_risk_history USING btree (asset_id, asset_version_name, day);

CREATE INDEX IF NOT EXISTS idx_dependency_vulns_asset_version_state ON public.dependency_vulns USING btree (asset_id, asset_version_name, state);
