--
-- PostgreSQL database dump
--

-- Dumped from database version 16.3 (Debian 16.3-1.pgdg120+1)
-- Dumped by pg_dump version 16.3 (Debian 16.3-1.pgdg120+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: semver; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS semver WITH SCHEMA public;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: affected_components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.affected_components (
    id text NOT NULL,
    source text,
    purl text,
    ecosystem text,
    scheme text,
    type text,
    name text,
    namespace text,
    qualifiers text,
    subpath text,
    version text,
    semver_introduced public.semver,
    semver_fixed public.semver,
    version_introduced text,
    version_fixed text
);


--
-- Name: asset_risk_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.asset_risk_history (
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    day date NOT NULL,
    sum_open_risk numeric,
    avg_open_risk numeric,
    max_open_risk numeric,
    min_open_risk numeric,
    sum_closed_risk numeric,
    avg_closed_risk numeric,
    max_closed_risk numeric,
    min_closed_risk numeric,
    open_dependency_vulns bigint,
    fixed_dependency_vulns bigint
);


--
-- Name: asset_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.asset_versions (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text NOT NULL,
    asset_id uuid NOT NULL,
    default_branch boolean DEFAULT false,
    slug text NOT NULL,
    type text NOT NULL,
    last_history_update timestamp with time zone,
    signing_pub_key text,
    metadata jsonb
);


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.assets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    slug text NOT NULL,
    central_dependency_vuln_management boolean DEFAULT false,
    project_id uuid NOT NULL,
    description text,
    type text NOT NULL,
    importance bigint DEFAULT 1,
    reachable_from_internet boolean DEFAULT false,
    confidentiality_requirement text DEFAULT 'high'::text NOT NULL,
    integrity_requirement text DEFAULT 'high'::text NOT NULL,
    availability_requirement text DEFAULT 'high'::text NOT NULL,
    repository_id text,
    repository_name text,
    last_history_update timestamp with time zone,
    cvss_automatic_ticket_threshold numeric(4,2),
    risk_automatic_ticket_threshold numeric(4,2),
    last_secret_scan timestamp with time zone,
    last_sast_scan timestamp with time zone,
    last_sca_scan timestamp with time zone,
    last_iac_scan timestamp with time zone,
    last_container_scan timestamp with time zone,
    last_dast_scan timestamp with time zone,
    signing_pub_key text,
    config_files jsonb,
    badge_secret uuid DEFAULT gen_random_uuid(),
    webhook_secret uuid DEFAULT gen_random_uuid(),
    external_entity_id text,
    external_entity_provider_id text
);


--
-- Name: attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.attestations (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    predicate_type text NOT NULL,
    scanner_id text NOT NULL,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    content jsonb
);


--
-- Name: casbin_rule; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.casbin_rule (
    id bigint NOT NULL,
    ptype character varying(100),
    v0 character varying(100),
    v1 character varying(100),
    v2 character varying(100),
    v3 character varying(100),
    v4 character varying(100),
    v5 character varying(100)
);


--
-- Name: casbin_rule_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.casbin_rule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: casbin_rule_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.casbin_rule_id_seq OWNED BY public.casbin_rule.id;


--
-- Name: component_dependencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.component_dependencies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_purl text,
    dependency_purl text,
    asset_id uuid,
    asset_version_name text,
    scanner_ids text,
    depth bigint
);


--
-- Name: component_projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.component_projects (
    project_key text NOT NULL,
    stars_count bigint,
    forks_count bigint,
    open_issues_count bigint,
    homepage text,
    license text,
    description text,
    score_card jsonb,
    score_card_score numeric,
    updated_at timestamp with time zone
);


--
-- Name: components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.components (
    purl text NOT NULL,
    component_type text,
    version text,
    license text,
    published timestamp with time zone,
    project_key text,
    is_license_overwritten boolean
);


--
-- Name: config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.config (
    key text NOT NULL,
    val text
);


--
-- Name: cpe_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.cpe_matches (
    match_criteria_id text NOT NULL,
    criteria text,
    part text,
    vendor text,
    product text,
    update text,
    edition text,
    language text,
    sw_edition text,
    target_sw text,
    target_hw text,
    other text,
    version text,
    version_end_excluding text,
    version_end_including text,
    version_start_including text,
    version_start_excluding text,
    vulnerable boolean
);


--
-- Name: cve_affected_component; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.cve_affected_component (
    affected_component_id text NOT NULL,
    cvecve text NOT NULL
);


--
-- Name: cve_cpe_match; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.cve_cpe_match (
    cpe_match_match_criteria_id text NOT NULL,
    cvecve text NOT NULL
);


--
-- Name: cves; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.cves (
    cve text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    date_published timestamp with time zone,
    date_last_modified timestamp with time zone,
    description text,
    cvss numeric(4,2),
    severity text,
    exploitability_score numeric(4,2),
    impact_score numeric(4,2),
    attack_vector text,
    attack_complexity text,
    privileges_required text,
    user_interaction text,
    scope text,
    confidentiality_impact text,
    integrity_impact text,
    availability_impact text,
    "references" text,
    cisa_exploit_add date,
    cisa_action_due date,
    cisa_required_action text,
    cisa_vulnerability_name text,
    epss numeric(6,5),
    percentile numeric(6,5),
    vector text
);


--
-- Name: cwes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.cwes (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    cwe text NOT NULL,
    description text
);


--
-- Name: dependency_vulns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.dependency_vulns (
    id text NOT NULL,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    message text,
    scanner_ids text NOT NULL,
    state text DEFAULT 'open'::text NOT NULL,
    last_detected timestamp with time zone DEFAULT now() NOT NULL,
    ticket_id text,
    ticket_url text,
    manual_ticket_creation boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    cve_id text,
    component_purl text,
    component_depth bigint,
    component_fixed_version text,
    effort bigint,
    risk_assessment bigint,
    raw_risk_assessment numeric,
    priority bigint,
    risk_recalculated_at timestamp with time zone
);


--
-- Name: exploits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.exploits (
    id text NOT NULL,
    published date,
    updated date,
    author text,
    type text,
    verified boolean,
    source_url text,
    description text,
    cve_id text,
    tags text,
    forks integer,
    watchers integer,
    subscribers integer,
    stars integer
);


--
-- Name: external_user_orgs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.external_user_orgs (
    external_user_id text NOT NULL,
    org_id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: external_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.external_users (
    id text NOT NULL,
    username text,
    avatar_url text
);


--
-- Name: first_party_vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.first_party_vulnerabilities (
    id text NOT NULL,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    message text,
    scanner_ids text NOT NULL,
    state text DEFAULT 'open'::text NOT NULL,
    last_detected timestamp with time zone DEFAULT now() NOT NULL,
    ticket_id text,
    ticket_url text,
    manual_ticket_creation boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    rule_id text,
    rule_name text,
    rule_description text,
    rule_help text,
    rule_help_uri text,
    rule_properties jsonb,
    uri text,
    start_line bigint,
    start_column bigint,
    end_line bigint,
    end_column bigint,
    snippet text,
    commit text,
    email text,
    author text,
    date text
);


--
-- Name: github_app_installations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.github_app_installations (
    installation_id bigint NOT NULL,
    org_id uuid,
    installation_created_webhook_received_time timestamp with time zone,
    settings_url text,
    target_type text,
    target_login text,
    target_avatar_url text
);


--
-- Name: github_app_installations_installation_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.github_app_installations_installation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: github_app_installations_installation_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.github_app_installations_installation_id_seq OWNED BY public.github_app_installations.installation_id;


--
-- Name: gitlab_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.gitlab_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    access_token text,
    gitlab_url text,
    org_id uuid
);


--
-- Name: gitlab_oauth2_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.gitlab_oauth2_tokens (
    id text DEFAULT gen_random_uuid() NOT NULL,
    access_token text,
    refresh_token text,
    expires_at bigint,
    scopes text,
    user_id text,
    gitlab_user_id bigint,
    expiry timestamp with time zone,
    verifier text,
    base_url text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    provider_id text,
    CONSTRAINT chk_gitlab_oauth2_tokens_user_id CHECK ((lower(user_id) <> 'NO_SESSION'::text))
);


--
-- Name: in_toto_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.in_toto_links (
    supply_chain_id text NOT NULL,
    step text NOT NULL,
    filename text,
    payload text,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    pat_id uuid,
    created_at timestamp with time zone
);


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    code text,
    organization_id uuid,
    email text
);


--
-- Name: jira_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.jira_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name character varying(255) NOT NULL,
    org_id uuid,
    access_token text,
    url text NOT NULL,
    user_email text,
    account_id text
);


--
-- Name: license_overwrite; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.license_overwrite (
    license_id text,
    organization_id uuid NOT NULL,
    component_purl text NOT NULL,
    justification text
);


--
-- Name: license_risks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.license_risks (
    id text NOT NULL,
    asset_version_name text NOT NULL,
    asset_id uuid NOT NULL,
    message text,
    scanner_ids text NOT NULL,
    state text DEFAULT 'open'::text NOT NULL,
    last_detected timestamp with time zone DEFAULT now() NOT NULL,
    ticket_id text,
    ticket_url text,
    manual_ticket_creation boolean DEFAULT false,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    final_license_decision text,
    component_purl text NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    contact_phone_number text,
    number_of_employees bigint,
    country text,
    industry text,
    critical_infrastructure boolean,
    iso27001 boolean,
    nist boolean,
    grundschutz boolean,
    slug text NOT NULL,
    description text,
    is_public boolean DEFAULT false,
    config_files jsonb,
    language text,
    external_entity_provider_id text
);


--
-- Name: pat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.pat (
    created_at timestamp with time zone,
    user_id text,
    pub_key text,
    description text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    fingerprint text,
    last_used_at timestamp with time zone,
    scopes text,
    deleted_at timestamp with time zone
);


--
-- Name: policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rego text,
    title text,
    predicate_type text,
    description text,
    organization_id uuid,
    opaque_id text
);


--
-- Name: project_enabled_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.project_enabled_policies (
    project_id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: project_risk_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.project_risk_history (
    project_id uuid NOT NULL,
    day date NOT NULL,
    sum_open_risk numeric,
    avg_open_risk numeric,
    max_open_risk numeric,
    min_open_risk numeric,
    sum_closed_risk numeric,
    avg_closed_risk numeric,
    max_closed_risk numeric,
    min_closed_risk numeric,
    open_dependency_vulns bigint,
    fixed_dependency_vulns bigint
);


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.projects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    organization_id uuid NOT NULL,
    slug text NOT NULL,
    description text,
    is_public boolean DEFAULT false,
    parent_id uuid,
    type text DEFAULT 'default'::text,
    repository_id text,
    repository_name text,
    config_files jsonb,
    external_entity_id text,
    external_entity_provider_id text
);


--
-- Name: supply_chain; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.supply_chain (
    supply_chain_id text NOT NULL,
    verified boolean,
    supply_chain_output_digest text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    asset_version_name text,
    asset_id uuid
);


--
-- Name: vuln_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.vuln_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    type text,
    vuln_id text,
    vuln_type text DEFAULT 'dependencyVuln'::text NOT NULL,
    user_id text,
    justification text,
    mechanical_justification text,
    arbitrary_json_data text,
    original_asset_version_name text
);


--
-- Name: weaknesses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.weaknesses (
    source text,
    type text,
    cve_id text NOT NULL,
    cwe_id text NOT NULL
);


--
-- Name: webhook_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.webhook_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    description text,
    url text,
    secret text,
    sbom_enabled boolean,
    vuln_enabled boolean,
    org_id uuid,
    project_id uuid
);


--
-- Name: casbin_rule id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.casbin_rule ALTER COLUMN id SET DEFAULT nextval('public.casbin_rule_id_seq'::regclass);


--
-- Name: github_app_installations installation_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations ALTER COLUMN installation_id SET DEFAULT nextval('public.github_app_installations_installation_id_seq'::regclass);


--
-- Name: affected_components affected_components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_components
    ADD CONSTRAINT affected_components_pkey PRIMARY KEY (id);


--
-- Name: asset_risk_history asset_risk_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_risk_history
    ADD CONSTRAINT asset_risk_history_pkey PRIMARY KEY (asset_version_name, asset_id, day);


--
-- Name: asset_versions asset_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_versions
    ADD CONSTRAINT asset_versions_pkey PRIMARY KEY (name, asset_id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: attestations attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT attestations_pkey PRIMARY KEY (predicate_type, scanner_id, asset_version_name, asset_id);


--
-- Name: casbin_rule casbin_rule_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.casbin_rule
    ADD CONSTRAINT casbin_rule_pkey PRIMARY KEY (id);


--
-- Name: component_dependencies component_dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT component_dependencies_pkey PRIMARY KEY (id);


--
-- Name: component_projects component_projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_projects
    ADD CONSTRAINT component_projects_pkey PRIMARY KEY (project_key);


--
-- Name: components components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (purl);


--
-- Name: config config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.config
    ADD CONSTRAINT config_pkey PRIMARY KEY (key);


--
-- Name: cpe_matches cpe_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cpe_matches
    ADD CONSTRAINT cpe_matches_pkey PRIMARY KEY (match_criteria_id);


--
-- Name: cve_affected_component cve_affected_component_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_affected_component
    ADD CONSTRAINT cve_affected_component_pkey PRIMARY KEY (affected_component_id, cvecve);


--
-- Name: cve_cpe_match cve_cpe_match_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_cpe_match
    ADD CONSTRAINT cve_cpe_match_pkey PRIMARY KEY (cpe_match_match_criteria_id, cvecve);


--
-- Name: cves cves_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cves
    ADD CONSTRAINT cves_pkey PRIMARY KEY (cve);


--
-- Name: cwes cwes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cwes
    ADD CONSTRAINT cwes_pkey PRIMARY KEY (cwe);


--
-- Name: dependency_vulns dependency_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependency_vulns
    ADD CONSTRAINT dependency_vulns_pkey PRIMARY KEY (id);


--
-- Name: exploits exploits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.exploits
    ADD CONSTRAINT exploits_pkey PRIMARY KEY (id);


--
-- Name: external_user_orgs external_user_orgs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_user_orgs
    ADD CONSTRAINT external_user_orgs_pkey PRIMARY KEY (external_user_id, org_id);


--
-- Name: external_users external_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_users
    ADD CONSTRAINT external_users_pkey PRIMARY KEY (id);


--
-- Name: first_party_vulnerabilities first_party_vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.first_party_vulnerabilities
    ADD CONSTRAINT first_party_vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: github_app_installations github_app_installations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations
    ADD CONSTRAINT github_app_installations_pkey PRIMARY KEY (installation_id);


--
-- Name: gitlab_integrations gitlab_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gitlab_integrations
    ADD CONSTRAINT gitlab_integrations_pkey PRIMARY KEY (id);


--
-- Name: gitlab_oauth2_tokens gitlab_oauth2_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gitlab_oauth2_tokens
    ADD CONSTRAINT gitlab_oauth2_tokens_pkey PRIMARY KEY (id);


--
-- Name: in_toto_links in_toto_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.in_toto_links
    ADD CONSTRAINT in_toto_links_pkey PRIMARY KEY (supply_chain_id, step, asset_version_name, asset_id);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: jira_integrations jira_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_integrations
    ADD CONSTRAINT jira_integrations_pkey PRIMARY KEY (id);


--
-- Name: license_overwrite license_overwrite_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_overwrite
    ADD CONSTRAINT license_overwrite_pkey PRIMARY KEY (organization_id, component_purl);


--
-- Name: license_risks license_risks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_risks
    ADD CONSTRAINT license_risks_pkey PRIMARY KEY (id, component_purl);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: pat pat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pat
    ADD CONSTRAINT pat_pkey PRIMARY KEY (id);


--
-- Name: policies policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_pkey PRIMARY KEY (id);


--
-- Name: project_enabled_policies project_enabled_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_enabled_policies
    ADD CONSTRAINT project_enabled_policies_pkey PRIMARY KEY (project_id, policy_id);


--
-- Name: project_risk_history project_risk_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_risk_history
    ADD CONSTRAINT project_risk_history_pkey PRIMARY KEY (project_id, day);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: supply_chain supply_chain_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain
    ADD CONSTRAINT supply_chain_pkey PRIMARY KEY (supply_chain_id);


--
-- Name: organizations uni_organizations_external_entity_provider_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT uni_organizations_external_entity_provider_id UNIQUE (external_entity_provider_id);


--
-- Name: organizations uni_organizations_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT uni_organizations_slug UNIQUE (slug);


--
-- Name: policies uni_policies_opaque_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT uni_policies_opaque_id UNIQUE (opaque_id);


--
-- Name: vuln_events vuln_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vuln_events
    ADD CONSTRAINT vuln_events_pkey PRIMARY KEY (id);


--
-- Name: weaknesses weaknesses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.weaknesses
    ADD CONSTRAINT weaknesses_pkey PRIMARY KEY (cve_id, cwe_id);


--
-- Name: webhook_integrations webhook_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_integrations
    ADD CONSTRAINT webhook_integrations_pkey PRIMARY KEY (id);


--
-- Name: asset_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS asset_id_idx ON public.component_dependencies USING btree (asset_id);


--
-- Name: asset_unique_external_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS asset_unique_external_entity ON public.assets USING btree (external_entity_id, external_entity_provider_id);


--
-- Name: asset_version_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS asset_version_name_idx ON public.component_dependencies USING btree (asset_version_name);


--
-- Name: component_purl_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS component_purl_idx ON public.component_dependencies USING btree (component_purl);


--
-- Name: dependency_purl_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS dependency_purl_idx ON public.component_dependencies USING btree (dependency_purl);


--
-- Name: idx_affected_components_p_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_p_url ON public.affected_components USING btree (purl);


--
-- Name: idx_affected_components_purl_without_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_purl_without_version ON public.affected_components USING btree (purl);


--
-- Name: idx_affected_components_semver_fixed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_semver_fixed ON public.affected_components USING btree (semver_fixed);


--
-- Name: idx_affected_components_semver_introduced; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_semver_introduced ON public.affected_components USING btree (semver_introduced);


--
-- Name: idx_affected_components_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_version ON public.affected_components USING btree (version);


--
-- Name: idx_affected_components_version_fixed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_version_fixed ON public.affected_components USING btree (version_fixed);


--
-- Name: idx_affected_components_version_introduced; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_affected_components_version_introduced ON public.affected_components USING btree (version_introduced);


--
-- Name: idx_app_project_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_project_slug ON public.assets USING btree (slug, project_id);


--
-- Name: idx_asset_versions_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_asset_versions_deleted_at ON public.asset_versions USING btree (deleted_at);


--
-- Name: idx_assets_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_assets_deleted_at ON public.assets USING btree (deleted_at);


--
-- Name: idx_attestations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_attestations_deleted_at ON public.attestations USING btree (deleted_at);


--
-- Name: idx_casbin_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS idx_casbin_rule ON public.casbin_rule USING btree (ptype, v0, v1, v2, v3, v4, v5);


--
-- Name: idx_cpe_matches_part; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_part ON public.cpe_matches USING btree (part);


--
-- Name: idx_cpe_matches_product; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_product ON public.cpe_matches USING btree (product);


--
-- Name: idx_cpe_matches_vendor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_vendor ON public.cpe_matches USING btree (vendor);


--
-- Name: idx_cpe_matches_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_version ON public.cpe_matches USING btree (version);


--
-- Name: idx_cpe_matches_version_end_excluding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_version_end_excluding ON public.cpe_matches USING btree (version_end_excluding);


--
-- Name: idx_cpe_matches_version_end_including; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_version_end_including ON public.cpe_matches USING btree (version_end_including);


--
-- Name: idx_cpe_matches_version_start_excluding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_version_start_excluding ON public.cpe_matches USING btree (version_start_excluding);


--
-- Name: idx_cpe_matches_version_start_including; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cpe_matches_version_start_including ON public.cpe_matches USING btree (version_start_including);


--
-- Name: idx_cwes_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_cwes_deleted_at ON public.cwes USING btree (deleted_at);


--
-- Name: idx_dependency_vulns_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_dependency_vulns_deleted_at ON public.dependency_vulns USING btree (deleted_at);


--
-- Name: idx_first_party_vulnerabilities_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_first_party_vulnerabilities_deleted_at ON public.first_party_vulnerabilities USING btree (deleted_at);


--
-- Name: idx_gitlab_integrations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_gitlab_integrations_deleted_at ON public.gitlab_integrations USING btree (deleted_at);


--
-- Name: idx_invitations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_invitations_deleted_at ON public.invitations USING btree (deleted_at);


--
-- Name: idx_jira_integrations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_jira_integrations_deleted_at ON public.jira_integrations USING btree (deleted_at);


--
-- Name: idx_license_risks_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_license_risks_deleted_at ON public.license_risks USING btree (deleted_at);


--
-- Name: idx_organizations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_organizations_deleted_at ON public.organizations USING btree (deleted_at);


--
-- Name: idx_organizations_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON public.organizations USING btree (slug);


--
-- Name: idx_project_org_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS idx_project_org_slug ON public.projects USING btree (organization_id, slug);


--
-- Name: idx_projects_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_projects_deleted_at ON public.projects USING btree (deleted_at);


--
-- Name: idx_vuln_events_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_vuln_events_deleted_at ON public.vuln_events USING btree (deleted_at);


--
-- Name: idx_webhook_integrations_deleted_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_webhook_integrations_deleted_at ON public.webhook_integrations USING btree (deleted_at);


--
-- Name: scanner_ids_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS scanner_ids_idx ON public.component_dependencies USING btree (scanner_ids);


--
-- Name: single-provider-token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS "single-provider-token" ON public.gitlab_oauth2_tokens USING btree (user_id, provider_id);


--
-- Name: unique_external_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX IF NOT EXISTS unique_external_entity ON public.projects USING btree (external_entity_id, external_entity_provider_id);


--
-- Name: attestations fk_asset_versions_attestations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT fk_asset_versions_attestations FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;


--
-- Name: component_dependencies fk_asset_versions_components; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_asset_versions_components FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id);


--
-- Name: dependency_vulns fk_asset_versions_dependency_vulns; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependency_vulns
    ADD CONSTRAINT fk_asset_versions_dependency_vulns FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;


--
-- Name: supply_chain fk_asset_versions_supply_chains; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.supply_chain
    ADD CONSTRAINT fk_asset_versions_supply_chains FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id);


--
-- Name: asset_versions fk_assets_asset_versions; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_versions
    ADD CONSTRAINT fk_assets_asset_versions FOREIGN KEY (asset_id) REFERENCES public.assets(id);


--
-- Name: component_dependencies fk_component_dependencies_asset_version; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_component_dependencies_asset_version FOREIGN KEY (asset_id, asset_version_name) REFERENCES public.asset_versions(asset_id, name) ON DELETE CASCADE;


--
-- Name: component_dependencies fk_component_dependencies_dependency; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_component_dependencies_dependency FOREIGN KEY (dependency_purl) REFERENCES public.components(purl) ON DELETE CASCADE;


--
-- Name: components fk_components_component_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.components
    ADD CONSTRAINT fk_components_component_project FOREIGN KEY (project_key) REFERENCES public.component_projects(project_key) ON DELETE CASCADE;


--
-- Name: component_dependencies fk_components_dependencies; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_dependencies
    ADD CONSTRAINT fk_components_dependencies FOREIGN KEY (component_purl) REFERENCES public.components(purl);


--
-- Name: cve_affected_component fk_cve_affected_component_affected_component; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_affected_component
    ADD CONSTRAINT fk_cve_affected_component_affected_component FOREIGN KEY (affected_component_id) REFERENCES public.affected_components(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: cve_affected_component fk_cve_affected_component_cve; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_affected_component
    ADD CONSTRAINT fk_cve_affected_component_cve FOREIGN KEY (cvecve) REFERENCES public.cves(cve) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: cve_cpe_match fk_cve_cpe_match_cpe_match; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_cpe_match
    ADD CONSTRAINT fk_cve_cpe_match_cpe_match FOREIGN KEY (cpe_match_match_criteria_id) REFERENCES public.cpe_matches(match_criteria_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: cve_cpe_match fk_cve_cpe_match_cve; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_cpe_match
    ADD CONSTRAINT fk_cve_cpe_match_cve FOREIGN KEY (cvecve) REFERENCES public.cves(cve) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: exploits fk_cves_exploits; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.exploits
    ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves(cve);


--
-- Name: weaknesses fk_cves_weaknesses; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.weaknesses
    ADD CONSTRAINT fk_cves_weaknesses FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;


--
-- Name: dependency_vulns fk_dependency_vulns_cve; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependency_vulns
    ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves(cve);


--
-- Name: external_user_orgs fk_external_user_orgs_external_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_user_orgs
    ADD CONSTRAINT fk_external_user_orgs_external_user FOREIGN KEY (external_user_id) REFERENCES public.external_users(id);


--
-- Name: external_user_orgs fk_external_user_orgs_org; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_user_orgs
    ADD CONSTRAINT fk_external_user_orgs_org FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: first_party_vulnerabilities fk_first_party_vulnerabilities_asset_version; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.first_party_vulnerabilities
    ADD CONSTRAINT fk_first_party_vulnerabilities_asset_version FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;


--
-- Name: in_toto_links fk_in_toto_links_asset_version; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.in_toto_links
    ADD CONSTRAINT fk_in_toto_links_asset_version FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;


--
-- Name: in_toto_links fk_in_toto_links_pat; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.in_toto_links
    ADD CONSTRAINT fk_in_toto_links_pat FOREIGN KEY (pat_id) REFERENCES public.pat(id) ON DELETE CASCADE;


--
-- Name: invitations fk_invitations_organization; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT fk_invitations_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id);


--
-- Name: license_risks fk_license_risks_asset_version; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.license_risks
    ADD CONSTRAINT fk_license_risks_asset_version FOREIGN KEY (asset_version_name, asset_id) REFERENCES public.asset_versions(name, asset_id) ON DELETE CASCADE;


--
-- Name: gitlab_integrations fk_organizations_git_lab_integrations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gitlab_integrations
    ADD CONSTRAINT fk_organizations_git_lab_integrations FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: github_app_installations fk_organizations_github_app_installations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations
    ADD CONSTRAINT fk_organizations_github_app_installations FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: jira_integrations fk_organizations_jira_integrations; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jira_integrations
    ADD CONSTRAINT fk_organizations_jira_integrations FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: projects fk_organizations_projects; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_organizations_projects FOREIGN KEY (organization_id) REFERENCES public.organizations(id);


--
-- Name: webhook_integrations fk_organizations_webhooks; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_integrations
    ADD CONSTRAINT fk_organizations_webhooks FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: policies fk_policies_organization; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT fk_policies_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: project_enabled_policies fk_project_enabled_policies_policy; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_enabled_policies
    ADD CONSTRAINT fk_project_enabled_policies_policy FOREIGN KEY (policy_id) REFERENCES public.policies(id);


--
-- Name: project_enabled_policies fk_project_enabled_policies_project; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_enabled_policies
    ADD CONSTRAINT fk_project_enabled_policies_project FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: assets fk_projects_assets; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT fk_projects_assets FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: projects fk_projects_children; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_projects_children FOREIGN KEY (parent_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: webhook_integrations fk_projects_webhooks; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_integrations
    ADD CONSTRAINT fk_projects_webhooks FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- PostgreSQL database dump complete
--

