// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"slices"
	"testing"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// every table of the migrated schema is listed in exactly one of the two lists, so a new table fails this test and cannot be silently missed by the data transfer export
var dataTransferExportedTables = []string{
	"advisories",
	"artifact_dependency_vulns",
	"artifact_license_risks",
	"artifacts",
	"asset_versions",
	"assets",
	"attestations",
	"compliance_postures",
	"component_projects",
	"components",
	"dependency_vulns",
	"external_references",
	"external_user_orgs",
	"external_users",
	"first_party_vulnerabilities",
	"frameworks_controls",
	"license_risks",
	"organizations",
	"projects",
	"sbom_merkle_edges",
	"sbom_merkle_nodes",
	"sboms",
	"vex_rules",
	"vuln_events",
}

var dataTransferNotExportedTables = []string{
	"access_tokens",
	"advisories_affected_packages",
	"affected_components",
	"affected_packages",
	"artifact_risk_history",
	"asset_risk_history",
	"casbin_rule",
	"compliance_component_implements_control_statements",
	"compliance_component_implements_controls",
	"compliance_components",
	"component_dependencies",
	"config",
	"cve_affected_component",
	"cve_relationships",
	"cves",
	"cwes",
	"dependency_proxy_secrets",
	"exploits",
	"github_app_installations",
	"gitlab_integrations",
	"gitlab_oauth2_tokens",
	"in_toto_links",
	"invitations",
	"jira_integrations",
	"license_overwrite",
	"logs",
	"malicious_affected_components",
	"malicious_packages",
	"mapped_controls",
	"policies",
	"project_enabled_policies",
	"project_risk_history",
	"release_items",
	"releases",
	"schema_migrations",
	"supply_chain",
	"trusted_entities",
	"upstream_vex_rules",
	"vex_rule_recommendations",
	"vuln_state_intervals",
	"weaknesses",
	"webhook_integrations",
}

// called from TestRunMigrations to reuse its migrated database instead of starting another container
func assertDatabaseTablesMatchExpectedTables(t *testing.T, db shared.DB) {
	t.Helper()
	var tables []string
	err := db.Raw(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`).Scan(&tables).Error
	require.NoError(t, err)

	expectedTables := slices.Concat(dataTransferExportedTables, dataTransferNotExportedTables)
	assert.ElementsMatch(t, expectedTables, tables, "the database tables changed, most likely a new table has been added. For that table decide whether it needs to be exported along side the existent tables in data_transfer_service.go or if the export logic changed in anyway.")
}
