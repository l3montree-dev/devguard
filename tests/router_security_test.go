// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/router"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/fx"
)

func roleRank(r shared.Role) int {
	switch r {
	case shared.RoleGuest:
		return 0
	case shared.RoleMember:
		return 1
	case shared.RoleAdmin:
		return 2
	case shared.RoleOwner:
		return 3
	default:
		panic("roleRank: unhandled shared.Role " + string(r))
	}
}

var routeMinLevel = map[string]shared.Role{
	"DELETE /api/v1/admin/external-orgs/:orgID/admins/:userID/":                                                                                              shared.RoleOwner,
	"DELETE /api/v1/organizations/:organization/":                                                                                                            shared.RoleOwner,
	"DELETE /api/v1/organizations/:organization/compliance-postures/components/:statementID/":                                                                shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/integrations/gitlab/:gitlab_integration_id/":                                                                 shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/integrations/jira/:jira_integration_id/":                                                                     shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/integrations/webhook/:id/":                                                                                   shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/invitation/:ID/":                                                                                             shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/members/:userID/":                                                                                            shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/pats/:tokenID/":                                                                                              shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/policies/:policyID/":                                                                                         shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/":                                                                                      shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/":                                                                    shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/external-references/:url/":                                           shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/members/:userID/":                                                    shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/pats/:tokenID/":                                                      shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/":                                             shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/:id/":                                shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/:id/events/":                           shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/":                     shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/components/:statementID/": shared.RoleMember,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/events/:eventID/":                             shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/:ruleId/":                                                  shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/components/:statementID/":                                          shared.RoleMember,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/integrations/webhook/:id/":                                                             shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/members/:userID/":                                                                      shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/pats/:tokenID/":                                                                        shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/policies/:policyID/":                                                                   shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/":                                                                  shared.RoleAdmin,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/items/:itemID/":                                                    shared.RoleAdmin,
	"DELETE /api/v1/pats/:tokenID/":                                                                                                                            shared.RoleMember,
	"GET /api/v1/.well-known/csaf-aggregator/aggregator.json/":                                                                                                 shared.RoleGuest,
	"GET /api/v1/admin/":                                                                                                                                       shared.RoleOwner,
	"GET /api/v1/admin/external-orgs/":                                                                                                                         shared.RoleOwner,
	"GET /api/v1/admin/organizations/:orgID/":                                                                                                                  shared.RoleOwner,
	"GET /api/v1/admin/settings/":                                                                                                                              shared.RoleOwner,
	"GET /api/v1/admin/statistics/usage/":                                                                                                                      shared.RoleOwner,
	"GET /api/v1/admin/statistics/vulnerabilities/":                                                                                                            shared.RoleOwner,
	"GET /api/v1/admin/users/:userID/":                                                                                                                         shared.RoleOwner,
	"GET /api/v1/compliance-components/":                                                                                                                       shared.RoleGuest,
	"GET /api/v1/compliance-components/:complianceComponentID/":                                                                                                shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/go":                                                                                                                  shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/go/*":                                                                                                                shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:package":                                                                                                        shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:package/":                                                                                                       shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:package/-/*":                                                                                                    shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:scope/:name":                                                                                                    shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:scope/:name/":                                                                                                   shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/npm/:scope/:name/-/*":                                                                                                shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/pypi/packages/*":                                                                                                     shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/pypi/simple/:package":                                                                                                shared.RoleGuest,
	"GET /api/v1/dependency-proxy/:secret/pypi/simple/:package/":                                                                                               shared.RoleGuest,
	"GET /api/v1/dependency-proxy/go":                                                                                                                          shared.RoleGuest,
	"GET /api/v1/dependency-proxy/go/*":                                                                                                                        shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:package":                                                                                                                shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:package/":                                                                                                               shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:package/-/*":                                                                                                            shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:scope/:name":                                                                                                            shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:scope/:name/":                                                                                                           shared.RoleGuest,
	"GET /api/v1/dependency-proxy/npm/:scope/:name/-/*":                                                                                                        shared.RoleGuest,
	"GET /api/v1/dependency-proxy/pypi/packages/*":                                                                                                             shared.RoleGuest,
	"GET /api/v1/dependency-proxy/pypi/simple/:package":                                                                                                        shared.RoleGuest,
	"GET /api/v1/dependency-proxy/pypi/simple/:package/":                                                                                                       shared.RoleGuest,
	"GET /api/v1/health/":                                                                                                                                      shared.RoleGuest,
	"GET /api/v1/info/":                                                                                                                                        shared.RoleGuest,
	"GET /api/v1/instance-settings/":                                                                                                                           shared.RoleGuest,
	"GET /api/v1/integrations/repositories/":                                                                                                                   shared.RoleGuest,
	"GET /api/v1/lookup/":                                                                                                                                      shared.RoleGuest,
	"GET /api/v1/oauth2/gitlab/:integrationName/":                                                                                                              shared.RoleGuest,
	"GET /api/v1/oauth2/gitlab/callback/:integrationName/":                                                                                                     shared.RoleGuest,
	"GET /api/v1/organizations/":                                                                                                                               shared.RoleGuest,
	"GET /api/v1/organizations/:organization/":                                                                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/compliance-postures/":                                                                                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/compliance-postures/:frameworkControlID/":                                                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/compliance-postures/oscal/":                                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/compliance-postures/stats/":                                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/config-files/:config-file/":                                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/content-tree/":                                                                                                    shared.RoleMember,
	"GET /api/v1/organizations/:organization/csaf/openpgp/":                                                                                                    shared.RoleGuest,
	"GET /api/v1/organizations/:organization/csaf/openpgp/:file/":                                                                                              shared.RoleGuest,
	"GET /api/v1/organizations/:organization/csaf/provider-metadata.json/":                                                                                     shared.RoleGuest,
	"GET /api/v1/organizations/:organization/dependency-proxy-urls/":                                                                                           shared.RoleMember,
	"GET /api/v1/organizations/:organization/dependency-vulns/":                                                                                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/first-party-vulns/":                                                                                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/integrations/finish-installation/":                                                                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/integrations/repositories/":                                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/members/":                                                                                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/metrics/":                                                                                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/pats/":                                                                                                            shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/policies/":                                                                                                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/policies/:policyID/":                                                                                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/":                                                                                                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/":                                                                                           shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/":                                                                                    shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/":                                                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/badges/:badge/":                                                           shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/compliance/":                                                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/compliance/:policy/":                                                      shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/components/licenses/":                                                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/config-files/:config-file/":                                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/":                                                                    shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/":                                                              shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/":                                                        shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/:version/":                                               shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/changes.csv/":                                                  shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/index.txt/":                                                    shared.RoleGuest,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/dependency-proxy-urls/":                                                   shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/external-references/":                                                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/in-toto/root.layout.json/":                                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/members/":                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/number-of-exploits/":                                                      shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/pats/":                                                                    shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/":                                                                    shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/":                                                  shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/":                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/:id/":                                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/affected-components/":                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifact-root-nodes/":                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/":                                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/badges/:badge/":            shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/csaf.json/":                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/openvex.json/":             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/sbom.json/":                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/sbom.pdf/":                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/sbom.xml/":                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/vex.json/":                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/vex.xml/":                  shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/vulnerability-report.pdf/": shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/attestations/":                                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/":                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/:frameworkControlID/":          shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/oscal/":                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/stats/":                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance/":                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance/:policy/":                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/components/":                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/components/licenses/":                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-graph/":                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/":                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/":               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/events/":        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/hints/":         shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/events/":                                           shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/":                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/":              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/events/":       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/in-toto/:supplyChainID/":                           shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/":                                    shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/":                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/metrics/":                                          shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/path-to-component/":                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/sarif.json/":                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/sbom.json/":                                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/stats/average-fixing-time/":                        shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/stats/component-risk/":                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/stats/risk-history/":                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/stats/risk-history/":                                                      shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/vex.json/":                                         shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/secrets/":                                                                 shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/":                                                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/:ruleId/":                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/recommendations/":                                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/recommendations/:dependencyVulnID/":                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/":                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/:frameworkControlID/":                                                   shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/oscal/":                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/stats/":                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/compliance/":                                                                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/components/":                                                                                shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/config-files/:config-file/":                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/dependency-proxy-urls/":                                                                     shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/dependency-vulns/":                                                                          shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/external/:providerID/":                                                                      shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/members/":                                                                                   shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/pats/":                                                                                      shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/policies/":                                                                                  shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/":                                                                                  shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/":                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/candidates/":                                                            shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/csaf.json/":                                                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/openvex.json/":                                                          shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/sbom.json/":                                                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/sbom.xml/":                                                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/stats/average-fixing-time/":                                             shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/stats/risk-history/":                                                    shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/vex.json/":                                                              shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/vex.xml/":                                                               shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/releases/candidates/":                                                                       shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/:projectSlug/resources/":                                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/projects/search/":                                                                                                 shared.RoleMember,
	"GET /api/v1/organizations/:organization/settings/":                                                                                                        shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/stats/vuln-statistics/":                                                                                           shared.RoleAdmin,
	"GET /api/v1/organizations/:organization/trigger-sync/":                                                                                                    shared.RoleMember,
	"GET /api/v1/pats/": shared.RoleMember,
	"GET /api/v1/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName/badges/:badge/": shared.RoleGuest,
	"GET /api/v1/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName/csaf.json/":     shared.RoleGuest,
	"GET /api/v1/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName/openvex.json/":  shared.RoleGuest,
	"GET /api/v1/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName/sbom.json/":     shared.RoleGuest,
	"GET /api/v1/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName/vex.json/":      shared.RoleGuest,
	"GET /api/v1/renovate/recommendation/":                                                      shared.RoleGuest,
	"GET /api/v1/trigger-sync/":                                                                 shared.RoleMember,
	"GET /api/v1/verify-supply-chain/":                                                          shared.RoleGuest,
	"GET /api/v1/vulndb/":                                                                       shared.RoleGuest,
	"GET /api/v1/vulndb/:cveID/":                                                                shared.RoleGuest,
	"GET /api/v1/vulndb/cve-ecosystem-distribution/":                                            shared.RoleGuest,
	"GET /api/v1/vulndb/list-ids-by-creation-date/":                                             shared.RoleGuest,
	"GET /api/v1/vulndb/purl-inspect/:purl":                                                     shared.RoleGuest,
	"GET /api/v1/whoami/":                                                                       shared.RoleGuest,
	"GET /v2/":                                                                                  shared.RoleGuest,
	"GET /v2/:registry/:image/blobs/:digest":                                                    shared.RoleGuest,
	"GET /v2/:registry/:image/manifests/:reference":                                             shared.RoleGuest,
	"GET /v2/:registry/:image/referrers/:digest":                                                shared.RoleGuest,
	"GET /v2/:registry/:image/tags/list":                                                        shared.RoleGuest,
	"GET /v2/:registry/:namespace/:image/blobs/:digest":                                         shared.RoleGuest,
	"GET /v2/:registry/:namespace/:image/manifests/:reference":                                  shared.RoleGuest,
	"GET /v2/:registry/:namespace/:image/referrers/:digest":                                     shared.RoleGuest,
	"GET /v2/:registry/:namespace/:image/tags/list":                                             shared.RoleGuest,
	"GET /v2/:secret/:registry/:namespace/:image/blobs/:digest":                                 shared.RoleGuest,
	"GET /v2/:secret/:registry/:namespace/:image/manifests/:reference":                          shared.RoleGuest,
	"GET /v2/:secret/:registry/:namespace/:image/referrers/:digest":                             shared.RoleGuest,
	"GET /v2/:secret/:registry/:namespace/:image/tags/list":                                     shared.RoleGuest,
	"GET /v2/:secret/:registry/:ns1/:ns2/:image/blobs/:digest":                                  shared.RoleGuest,
	"GET /v2/:secret/:registry/:ns1/:ns2/:image/manifests/:reference":                           shared.RoleGuest,
	"GET /v2/:secret/:registry/:ns1/:ns2/:image/referrers/:digest":                              shared.RoleGuest,
	"GET /v2/:secret/:registry/:ns1/:ns2/:image/tags/list":                                      shared.RoleGuest,
	"HEAD /v2/": shared.RoleGuest,
	"HEAD /v2/:registry/:image/blobs/:digest":                                                                                                                shared.RoleGuest,
	"HEAD /v2/:registry/:image/manifests/:reference":                                                                                                         shared.RoleGuest,
	"HEAD /v2/:registry/:namespace/:image/blobs/:digest":                                                                                                     shared.RoleGuest,
	"HEAD /v2/:registry/:namespace/:image/manifests/:reference":                                                                                              shared.RoleGuest,
	"HEAD /v2/:secret/:registry/:namespace/:image/blobs/:digest":                                                                                             shared.RoleGuest,
	"HEAD /v2/:secret/:registry/:namespace/:image/manifests/:reference":                                                                                      shared.RoleGuest,
	"HEAD /v2/:secret/:registry/:ns1/:ns2/:image/blobs/:digest":                                                                                              shared.RoleGuest,
	"HEAD /v2/:secret/:registry/:ns1/:ns2/:image/manifests/:reference":                                                                                       shared.RoleGuest,
	"PATCH /api/v1/admin/assets/:assetID/":                                                                                                                   shared.RoleOwner,
	"PATCH /api/v1/admin/settings/":                                                                                                                          shared.RoleOwner,
	"PATCH /api/v1/organizations/:organization/":                                                                                                             shared.RoleAdmin,
	"PATCH /api/v1/organizations/:organization/projects/:projectSlug/":                                                                                       shared.RoleAdmin,
	"PATCH /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/":                                                                     shared.RoleAdmin,
	"PATCH /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/:id/":                                 shared.RoleAdmin,
	"PATCH /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/":                                                                   shared.RoleAdmin,
	"POST /api/v1/accept-invitation/":                                                                                                                        shared.RoleMember,
	"POST /api/v1/admin/daemons/asset-pipeline-all/trigger/":                                                                                                 shared.RoleOwner,
	"POST /api/v1/admin/daemons/asset-pipeline-single/trigger/":                                                                                              shared.RoleOwner,
	"POST /api/v1/admin/daemons/fixed-versions/trigger/":                                                                                                     shared.RoleOwner,
	"POST /api/v1/admin/daemons/open-source-insights/trigger/":                                                                                               shared.RoleOwner,
	"POST /api/v1/admin/daemons/vulndb/trigger/":                                                                                                             shared.RoleOwner,
	"POST /api/v1/attestations/":                                                                                                                             shared.RoleMember,
	"POST /api/v1/dependency-proxy/:secret/npm/*":                                                                                                            shared.RoleGuest,
	"POST /api/v1/dependency-proxy/npm/*":                                                                                                                    shared.RoleGuest,
	"POST /api/v1/organizations/":                                                                                                                            shared.RoleMember,
	"POST /api/v1/organizations/:organization/compliance-postures/:frameworkControlID/":                                                                      shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/compliance-postures/:frameworkControlID/components/:complianceComponentID/":                                    shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/integrations/gitlab/test-and-save/":                                                                            shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/integrations/jira/test-and-save/":                                                                              shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/integrations/webhook/test-and-save/":                                                                           shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/integrations/webhook/test/":                                                                                    shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/members/":                                                                                                      shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/pats/":                                                                                                         shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/policies/":                                                                                                     shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/":                                                                                                     shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/":                                                                                 shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/external-references/":                                                  shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/external-references/sync/":                                             shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/in-toto/":                                                              shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/integrations/gitlab/autosetup/":                                        shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/members/":                                                              shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/pats/":                                                                 shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/pipeline-trigger/":                                                     shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/":                                                                 shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/advisory/":                                      shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/":                                     shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/sync-external-sources/": shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/:frameworkControlID/":       shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/:frameworkControlID/components/:complianceComponentID/": shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/components/licenses/refresh/":                                               shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/":                                        shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/:dependencyVulnID/mitigate/":                               shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/batch/":                                                    shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/dependency-vulns/sync/":                                                     shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/":                                       shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/:firstPartyVulnID/mitigate/":                              shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/first-party-vulns/batch/":                                                   shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/":                                                             shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/":                                              shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/final-license-decision/":                       shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/license-risks/:licenseRiskID/mitigate/":                                     shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/make-default/":                                                              shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/sbom-file/":                                                                                        shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/signing-key/":                                                                                      shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/":                                                                                        shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/vex-rules/test/":                                                                                   shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/:frameworkControlID/":                                                                            shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/:frameworkControlID/components/:complianceComponentID/":                                          shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/external/:providerID/":                                                                                               shared.RoleMember,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/integrations/webhook/test-and-save/":                                                                                 shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/integrations/webhook/test/":                                                                                          shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/members/":                                                                                                            shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/pats/":                                                                                                               shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/releases/":                                                                                                           shared.RoleAdmin,
	"POST /api/v1/organizations/:organization/projects/:projectSlug/releases/:releaseID/items/":                                                                                          shared.RoleAdmin,
	"POST /api/v1/pats/":                                       shared.RoleMember,
	"POST /api/v1/pats/revoke-by-private-key/":                 shared.RoleMember,
	"POST /api/v1/sarif-scan-unauthenticated/":                 shared.RoleGuest,
	"POST /api/v1/sarif-scan/":                                 shared.RoleMember,
	"POST /api/v1/scan-unauthenticated/":                       shared.RoleGuest,
	"POST /api/v1/scan/":                                       shared.RoleMember,
	"POST /api/v1/vex/":                                        shared.RoleMember,
	"POST /api/v1/webhook/":                                    shared.RoleGuest,
	"POST /api/v2/sarif-scan-unauthenticated/":                 shared.RoleGuest,
	"POST /api/v2/sarif-scan/":                                 shared.RoleMember,
	"POST /api/v2/scan-unauthenticated/":                       shared.RoleGuest,
	"POST /api/v2/scan/":                                       shared.RoleMember,
	"PUT /api/v1/admin/external-orgs/:orgID/admins/:userMail/": shared.RoleOwner,
	"PUT /api/v1/organizations/:organization/compliance-postures/components/:statementID/":                                                                shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/config-files/:config-file/":                                                                                  shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/integrations/webhook/:id/":                                                                                   shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/members/:userID/":                                                                                            shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/policies/:policyID/":                                                                                         shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/config-files/:config-file/":                                          shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/members/:userID/":                                                    shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/artifacts/:artifactName/":                     shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/compliance-postures/components/:statementID/": shared.RoleMember,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/compliance-postures/components/:statementID/":                                          shared.RoleMember,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/config-files/:config-file/":                                                            shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/integrations/webhook/:id/":                                                             shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/members/:userID/":                                                                      shared.RoleAdmin,
	"PUT /api/v1/organizations/:organization/projects/:projectSlug/policies/:policyID/":                                                                   shared.RoleAdmin,
}

// accessLevelFor is a strict lookup - every route from e.Routes() must be
// declared in routeMinLevel. A missing entry fails the test immediately
// rather than silently assuming a default, so a newly added route can't
// slip through unclassified.
func accessLevelFor(t *testing.T, method, path string) shared.Role {
	t.Helper()
	lvl, ok := routeMinLevel[method+" "+path]
	if !ok {
		t.Fatalf("route %s %s has no entry in routeMinLevel - every route must be explicitly classified", method, path)
	}
	return lvl
}

var echoParamNameRe = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

var (
	actorOwnerID          = uuid.New().String()
	actorAdminID          = uuid.New().String()
	actorReadOnlyMemberID = uuid.New().String()
)

const actorPublicVisitor = "test-public-visitor"

// fixedIntotoTestKey is a throwaway ECDSA key with no security value - it
// only exists so InToToController has a signing key to load in tests, in
// place of the /intoto-private-key.pem deployment secret production mounts.
const fixedIntotoTestKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1AoltK51PFjgDcxQ
/KYmjcVbjNVLACGHMLr2eneQwk6hRANCAARrS78QS2zqpDH+Lk3Z770lFjjGBJa2
RLL6+9Pwzv++nBR7RcrK6WkMIMgpVISkZFaKBgjygJnKe2xIPoR0ndOo
-----END PRIVATE KEY-----
`

func setupIntotoTestKey(t *testing.T) {
	t.Helper()
	keyPath := t.TempDir() + "/intoto-test-key.pem"
	if err := os.WriteFile(keyPath, []byte(fixedIntotoTestKey), 0600); err != nil {
		t.Fatalf("failed to write intoto test key: %v", err)
	}
	t.Setenv("INTOTO_PRIVATE_KEY_PATH", keyPath)
}

type seededResources struct {
	orgSlug               string
	projectSlug           string
	assetSlug             string
	assetVersionSlug      string
	dependencyProxySecret string
}

// Parent-scoping params must resolve to the real seeded rows, or every
// request 404s at ResourceFetchMiddleware before reaching the RBAC check
// under test; everything else gets a dummy value.
func fillParams(path string, seed seededResources) string {
	named := map[string]string{
		"organization":     seed.orgSlug,
		"project":          seed.projectSlug,
		"projectSlug":      seed.projectSlug,
		"assetSlug":        seed.assetSlug,
		"assetVersionSlug": seed.assetVersionSlug,
		"secret":           seed.dependencyProxySecret,
	}
	filled := echoParamNameRe.ReplaceAllStringFunc(path, func(m string) string {
		name := strings.TrimPrefix(m, ":")
		if v, ok := named[name]; ok {
			return v
		}
		// A well-formed but nonexistent UUID, not "test-id": several
		// handlers query the DB with the raw param before any RBAC check
		// runs, and a non-UUID string trips a DB-level cast error (500)
		// that has nothing to do with authorization.
		return uuid.NewString()
	})
	// risk-history requires start/end query params before it even reaches RBAC.
	if strings.Contains(filled, "/risk-history/") {
		filled += "?start=2020-01-01&end=2030-01-01"
	}
	return filled
}

func buildFullRouterServer(t *testing.T, public bool) (*echo.Echo, *TestApp) {
	t.Helper()

	db, pool, terminate := InitDatabaseContainer("../initdb.sql")
	t.Cleanup(terminate)

	setupIntotoTestKey(t)

	connCfg := pool.Config().ConnConfig
	t.Setenv("POSTGRES_HOST", connCfg.Host)
	t.Setenv("POSTGRES_PORT", strconv.Itoa(int(connCfg.Port)))
	t.Setenv("POSTGRES_USER", connCfg.User)
	t.Setenv("POSTGRES_PASSWORD", connCfg.Password)
	t.Setenv("POSTGRES_DB", connCfg.Database)
	// CSAFController.GetAggregatorJSON reads API_URL directly and 500s if unset.
	t.Setenv("API_URL", "http://localhost")

	patService := mocks.NewPersonalAccessTokenService(t)
	patService.On("VerifyRequestSignature", mock.Anything, mock.Anything).Maybe().
		Return(func(_ context.Context, req *http.Request) (shared.AuthSession, error) {
			actor := req.Header.Get("X-Test-Actor")
			if actor == "" || actor == actorPublicVisitor {
				return nil, fmt.Errorf("no session for public visitor")
			}
			return shared.NewSession(actor, shared.SessionActorUser, []string{"manage", "scan"}, false), nil
		})
	// InstanceAdminMiddleware (admin_router.go): none of this file's actors are
	// real instance admins, so /admin/* must always deny them (see routeMinLevel's
	// shared.RoleOwner doc comment).
	patService.On("VerifyAdminRequest", mock.Anything).Maybe().Return(false, nil)

	adminClient := mocks.NewAdminClient(t)
	adminClient.On("GetIdentity", mock.Anything, mock.Anything).Maybe().
		Return(func(_ context.Context, userID string) (client.Identity, error) {
			return client.Identity{Id: userID, Traits: map[string]any{"email": userID + "@test.local"}}, nil
		})
	adminClient.On("GetIdentityWithCredentials", mock.Anything, mock.Anything).Maybe().
		Return(func(_ context.Context, userID string) (client.Identity, error) {
			return client.Identity{Id: userID, Traits: map[string]any{"email": userID + "@test.local"}}, nil
		})
	adminClient.On("ListUser", mock.Anything).Maybe().
		Return(func(client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error) {
			ids := []string{actorOwnerID, actorAdminID, actorReadOnlyMemberID}
			identities := make([]client.Identity, 0, len(ids))
			for _, id := range ids {
				identities = append(identities, client.Identity{Id: id, Traits: map[string]any{"email": id + "@test.local"}})
			}
			return identities, nil
		})

	var apiServer api.Server
	app, fxApp := NewTestAppWithT(t, db, pool, &TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Provide(api.NewServer),
			router.RouterModule,
			fx.Decorate(func(shared.PersonalAccessTokenService) shared.PersonalAccessTokenService {
				return patService
			}),
			fx.Decorate(func(shared.AdminClient) shared.AdminClient {
				return adminClient
			}),
			fx.Invoke(func(router.Routers) {}),
			fx.Populate(&apiServer),
		},
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = fxApp.Stop(ctx)
	})

	e := apiServer.Echo
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}
		_ = c.NoContent(code)
	}

	return e, app
}

// Uses the real service layer (not raw db.Create) so production's RBAC
// bootstrap (BootstrapOrg/BootstrapProject/BootstrapAsset) actually runs -
// that's what gives actorReadOnlyMemberID/actorAdminID's org-level role read/
// write access at the project/asset level too, via the same role-name
// policies BootstrapProject/BootstrapAsset set up.
//
// slugSuffix must be unique per call within a test run: routes at or above
// their own required level actually mutate/delete the seeded rows (no
// transaction rollback wraps requests), so each actor level needs its own
// fixture rather than sharing one that a previous actor may have torn down.
func seedRBACFixture(t *testing.T, e *echo.Echo, app *TestApp, public bool, slugSuffix string) seededResources {
	t.Helper()

	ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())
	ownerSession := shared.NewSession(actorOwnerID, shared.SessionActorUser, []string{"manage", "scan"}, false)
	shared.SetSession(ctx, ownerSession)

	org := &models.Org{Name: "Test Org", Slug: "test-org-" + slugSuffix, IsPublic: public}
	if err := app.OrgService.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("failed to seed org: %v", err)
	}

	project := &models.Project{Name: "Test Project", Slug: "test-project-" + slugSuffix, OrganizationID: org.ID, IsPublic: public}
	if err := app.ProjectService.CreateProject(ctx, project); err != nil {
		t.Fatalf("failed to seed project: %v", err)
	}

	rbac := shared.GetRBAC(ctx)
	asset := models.Asset{Name: "Test Asset", Slug: "test-asset", ProjectID: project.ID, IsPublic: public}
	createdAsset, err := app.AssetService.CreateAsset(ctx.Request().Context(), rbac, ownerSession, asset)
	if err != nil {
		t.Fatalf("failed to seed asset: %v", err)
	}

	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       createdAsset.ID,
		DefaultBranch: true,
		Slug:          "main",
		Type:          "branch",
	}
	if err := app.DB.Create(&assetVersion).Error; err != nil {
		t.Fatalf("failed to seed asset version: %v", err)
	}

	memberSession := shared.NewSession(actorReadOnlyMemberID, shared.SessionActorUser, nil, false)
	if err := rbac.GrantRole(ctx.Request().Context(), memberSession, shared.RoleMember); err != nil {
		t.Fatalf("failed to grant read-only member role: %v", err)
	}

	adminSession := shared.NewSession(actorAdminID, shared.SessionActorUser, nil, false)
	if err := rbac.GrantRole(ctx.Request().Context(), adminSession, shared.RoleAdmin); err != nil {
		t.Fatalf("failed to grant admin role: %v", err)
	}

	proxySecret := models.DependencyProxySecret{OrgID: &org.ID}
	if err := app.DB.Create(&proxySecret).Error; err != nil {
		t.Fatalf("failed to seed dependency proxy secret: %v", err)
	}

	return seededResources{
		orgSlug:               org.Slug,
		projectSlug:           project.Slug,
		assetSlug:             createdAsset.Slug,
		assetVersionSlug:      assetVersion.Slug,
		dependencyProxySecret: proxySecret.Secret.String(),
	}
}

// actorsByLevel: every access level this codebase's RBAC recognizes, and the
// actor seeded to hold exactly that level.
var actorsByLevel = []struct {
	role  shared.Role
	actor string
}{
	{shared.RoleGuest, actorPublicVisitor},
	{shared.RoleMember, actorReadOnlyMemberID},
	{shared.RoleAdmin, actorAdminID},
	{shared.RoleOwner, actorOwnerID},
}

// runAccessLevelSweep is the outer loop (every access level) x inner loop
// (every route): for each combination it builds one request as that level's
// actor and executes it against e, then asserts the route's required level
// either blocks or allows that actor.
// selfDestructivePaths delete the exact org/project/asset/assetVersion the
// fixture seeded, so they must run after every other route in the sweep -
// otherwise a sufficiently-privileged actor tears down its own fixture
// mid-sweep and every route checked afterward 404s/500s for an unrelated reason.
var selfDestructivePaths = map[string]bool{
	"DELETE /api/v1/organizations/:organization/":                                                                true,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/":                                          true,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/":                        true,
	"DELETE /api/v1/organizations/:organization/projects/:projectSlug/assets/:assetSlug/refs/:assetVersionSlug/": true,
}

func runAccessLevelSweep(t *testing.T, e *echo.Echo, app *TestApp, public bool) {
	t.Helper()

	var routes, deferred []*echo.Route
	for _, route := range e.Routes() {
		if selfDestructivePaths[route.Method+" "+route.Path] {
			deferred = append(deferred, route)
			continue
		}
		routes = append(routes, route)
	}
	routes = append(routes, deferred...)

	for _, a := range actorsByLevel {
		t.Run(string(a.role), func(t *testing.T) {
			seed := seedRBACFixture(t, e, app, public, string(a.role))
			for _, route := range routes {
				if route.Method == "echo_route_not_found" {
					continue
				}

				required := accessLevelFor(t, route.Method, route.Path)
				if public && route.Method == http.MethodGet && required == shared.RoleMember {
					required = shared.RoleGuest
				}

				req := httptest.NewRequest(route.Method, fillParams(route.Path, seed), nil)
				req.Header.Set("X-Test-Actor", a.actor)
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, req)

				if roleRank(a.role) >= roleRank(required) {
					// Sub-resource :id params are random UUIDs with no seeded row, so a
					// legitimate 404 is expected even for a sufficiently privileged actor.
					assert.Less(t, rec.Code, 500, "route %s %s (%s access is sufficient, needs %s) returned %d",
						route.Method, route.Path, a.role, required, rec.Code)
					continue
				}
				assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}, rec.Code,
					"route %s %s returned unexpected status %d for a %s actor (want 401/403/404)", route.Method, route.Path, rec.Code, a.role)
			}
		})
	}
}

func TestRoutesEnforceAccessLevelsOnPublicResources(t *testing.T) {
	e, app := buildFullRouterServer(t, true)
	runAccessLevelSweep(t, e, app, true)
}

func TestRoutesEnforceAccessLevelsOnPrivateResources(t *testing.T) {
	e, app := buildFullRouterServer(t, false)
	runAccessLevelSweep(t, e, app, false)
}
