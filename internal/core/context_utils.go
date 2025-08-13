// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package core

import (
	"context"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/echohttp"
	"github.com/l3montree-dev/devguard/internal/utils"

	"github.com/ory/client-go"
)

type AuthSession interface {
	GetUserID() string
	GetScopes() []string
}

func GetThirdPartyIntegration(ctx Context) IntegrationAggregate {
	return ctx.Get("thirdPartyIntegration").(IntegrationAggregate)
}

func SetThirdPartyIntegration(ctx Context, i IntegrationAggregate) {
	ctx.Set("thirdPartyIntegration", i)
}

type AdminClient interface {
	ListUser(client client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error)
	GetIdentityFromCookie(ctx context.Context, cookie string) (client.Identity, error)
	GetIdentity(ctx context.Context, userID string) (client.Identity, error)
	GetIdentityWithCredentials(ctx context.Context, userID string) (client.Identity, error)
}

type adminClientImplementation struct {
	apiClient *client.APIClient
}

func NewAdminClient(client *client.APIClient) adminClientImplementation {
	return adminClientImplementation{
		apiClient: client,
	}
}

func (a adminClientImplementation) GetIdentityFromCookie(ctx context.Context, cookie string) (client.Identity, error) {
	session, _, err := a.apiClient.FrontendAPI.ToSession(ctx).Cookie(cookie).Execute()
	if err != nil {
		return client.Identity{}, fmt.Errorf("could not get identity from cookie: %w", err)
	}
	if session.Identity == nil {
		return client.Identity{}, fmt.Errorf("identity not found in session")
	}
	return *session.Identity, nil
}

func (a adminClientImplementation) ListUser(request client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error) {
	clients, _, err := a.apiClient.IdentityAPI.ListIdentitiesExecute(request)
	return clients, err
}

func (a adminClientImplementation) GetIdentityWithCredentials(ctx context.Context, userID string) (client.Identity, error) {
	resp, _, err := a.apiClient.IdentityAPI.GetIdentity(ctx, userID).IncludeCredential([]string{"oidc"}).Execute()
	if err != nil {
		return client.Identity{}, err
	}
	return *resp, nil
}

func (a adminClientImplementation) GetIdentity(ctx context.Context, userID string) (client.Identity, error) {
	request, _, err := a.apiClient.IdentityAPI.GetIdentity(ctx, userID).Execute()
	if err != nil {
		return *request, err
	}
	return *request, nil
}

func SetAuthAdminClient(ctx Context, i AdminClient) {
	ctx.Set("authAdminClient", i)
}

func GetAuthAdminClient(ctx Context) AdminClient {
	return ctx.Get("authAdminClient").(AdminClient)
}

func GetVulnID(ctx Context) (string, models.VulnType, error) {
	dependencyVulnID := ctx.Param("dependencyVulnID")
	if dependencyVulnID != "" {
		return dependencyVulnID, models.VulnTypeDependencyVuln, nil
	}
	dependencyVulnIDFromGet, ok := ctx.Get("dependencyVulnID").(string)
	if ok && dependencyVulnIDFromGet != "" {
		return dependencyVulnIDFromGet, models.VulnTypeDependencyVuln, nil
	}

	firstPartyVulnID := ctx.Param("firstPartyVulnID")
	if firstPartyVulnID != "" {
		return firstPartyVulnID, models.VulnTypeFirstPartyVuln, nil
	}
	firstPartyVulnIDFromGet, ok := ctx.Get("firstPartyVulnID").(string)
	if ok && firstPartyVulnIDFromGet != "" {
		return firstPartyVulnIDFromGet, models.VulnTypeFirstPartyVuln, nil
	}

	licenseRiskID := ctx.Param("licenseRiskID")
	if licenseRiskID != "" {
		return licenseRiskID, models.VulnTypeLicenseRisk, nil
	}
	licenseRiskIDFromGet, ok := ctx.Get("licenseRiskID").(string)
	if ok && licenseRiskIDFromGet != "" {
		return licenseRiskIDFromGet, models.VulnTypeLicenseRisk, nil
	}

	return "", "", fmt.Errorf("could not get vuln id")
}

func SetRBAC(ctx Context, rbac AccessControl) {
	ctx.Set("rbac", rbac)
}

func SetOrg(c Context, org models.Org) {
	c.Set("organization", org)
}

func SetOrgSlug(ctx Context, orgSlug string) {
	ctx.Set("orgSlug", orgSlug)
}

func GetOrg(c Context) models.Org {
	return c.Get("organization").(models.Org)
}

func HasOrganization(c Context) bool {
	_, ok := c.Get("organization").(models.Org)
	return ok
}
func HasProject(c Context) bool {
	_, ok := c.Get("project").(models.Project)
	return ok
}
func GetRBAC(ctx Context) AccessControl {
	return ctx.Get("rbac").(AccessControl)
}

func SetIsPublicRequest(ctx Context) {
	ctx.Set("publicRequest", true)
}

func IsPublicRequest(ctx Context) bool {
	return ctx.Get("publicRequest") != nil
}

func GetOryClient(ctx Context) *client.APIClient {
	return ctx.Get("ory").(*client.APIClient)
}

func GetSession(ctx Context) AuthSession {
	return ctx.Get("session").(AuthSession)
}

func SetSession(ctx Context, session AuthSession) {
	ctx.Set("session", session)
}

func GetParam(ctx Context, param string) string {
	v := ctx.Param(param)
	if v == "" {
		fallback := ctx.Get(param)
		if fallback == nil {
			return ""
		}
		return fallback.(string)
	}
	return v
}

func GetProjectSlug(ctx Context) (string, error) {
	projectID := GetParam(ctx, "projectSlug")
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetOrgSlug(ctx Context) (string, error) {
	orgSlug := GetParam(ctx, "orgSlug")
	if orgSlug == "" {
		return "", fmt.Errorf("could not get org slug")
	}
	return orgSlug, nil
}

func SetProjectSlug(ctx Context, projectSlug string) {
	ctx.Set("projectSlug", projectSlug)
}

func SetAssetSlug(ctx Context, assetSlug string) {
	ctx.Set("assetSlug", assetSlug)
}

func GetAssetSlug(ctx Context) (string, error) {
	assetSlug := GetParam(ctx, "assetSlug")
	if assetSlug == "" {
		return "", fmt.Errorf("could not get asset slug")
	}
	return assetSlug, nil
}

func GetAssetVersionSlug(ctx Context) (string, error) {
	assetVersionSlug := GetParam(ctx, "assetVersionSlug")
	if assetVersionSlug == "" {
		return "", fmt.Errorf("could not get asset version slug")
	}
	return assetVersionSlug, nil
}

func GetAsset(ctx Context) models.Asset {
	return ctx.Get("asset").(models.Asset)
}

func SetAsset(ctx Context, asset models.Asset) {
	ctx.Set("asset", asset)
}

func GetAssetVersion(ctx Context) models.AssetVersion {
	return ctx.Get("assetVersion").(models.AssetVersion)
}

func MaybeGetAssetVersion(ctx Context) (models.AssetVersion, error) {
	assetVersion, ok := ctx.Get("assetVersion").(models.AssetVersion)
	if !ok {
		return models.AssetVersion{}, fmt.Errorf("could not get asset version")
	}
	return assetVersion, nil
}

func SetAssetVersion(ctx Context, assetVersion models.AssetVersion) {
	ctx.Set("assetVersion", assetVersion)
}

func SetProject(ctx Context, project models.Project) {
	ctx.Set("project", project)
}

func GetProject(ctx Context) models.Project {
	return ctx.Get("project").(models.Project)
}

func GetAttestation(ctx Context) models.Attestation {
	return ctx.Get("attestation").(models.Attestation)
}

func SetAttestation(ctx Context, attestation models.Attestation) {
	ctx.Set("attestation", attestation)
}

func GetRepositoryID(asset *models.Asset) (string, error) {
	if asset.RepositoryID != nil {
		return *asset.RepositoryID, nil
	}
	if asset.ExternalEntityID != nil {
		return *asset.ExternalEntityID, nil
	}

	return "", fmt.Errorf("could not get repository id from asset")
}

type PageInfo struct {
	PageSize int `json:"pageSize"`
	Page     int `json:"page"`
}

func (p PageInfo) ApplyOnDB(db DB) DB {
	return db.Offset((p.Page - 1) * p.PageSize).Limit(p.PageSize)
}

type Paged[T any] struct {
	PageInfo
	Total int64 `json:"total"`
	Data  []T   `json:"data"`
}

func (p Paged[T]) Map(f func(T) any) Paged[any] {
	data := make([]any, len(p.Data))
	for i, d := range p.Data {
		data[i] = f(d)
	}
	return Paged[any]{
		PageInfo: p.PageInfo,
		Total:    p.Total,
		Data:     data,
	}
}

func NewPaged[T any](pageInfo PageInfo, total int64, data []T) Paged[T] {
	return Paged[T]{
		PageInfo: pageInfo,
		Total:    total,
		Data:     data,
	}
}

func GetPageInfo(ctx Context) PageInfo {
	page, _ := strconv.Atoi(ctx.QueryParam("page"))
	if page <= 0 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(ctx.QueryParam("pageSize"))
	switch {
	case pageSize > 100:
		pageSize = 100
	case pageSize <= 0:
		pageSize = 10
	}

	return PageInfo{
		Page:     page,
		PageSize: pageSize,
	}
}

type FilterQuery struct {
	field    string
	value    string
	operator string
}

func GetFilterQuery(ctx Context) []FilterQuery {
	// get all query params, which start with filterQuery
	query := ctx.QueryParams()
	filterQuerys := []FilterQuery{}
	for key := range query {
		if !strings.HasPrefix(key, "filterQuery") {
			continue
		}

		// get the value
		value := query.Get(key)
		// extract the field and operator from the key
		// it looks like this: filterQuery[cve.cvss][is]=10

		// remove the filterQuery prefix
		key = strings.TrimPrefix(key, "filterQuery")
		// use a regex
		// get the field
		field := strings.Split(key, "[")[1]
		field = strings.TrimSuffix(field, "]")

		// get the operator
		operator := strings.Split(key, "[")[2]
		operator = strings.TrimSuffix(operator, "]")

		filterQuerys = append(filterQuerys, FilterQuery{
			field:    field,
			value:    value,
			operator: operator,
		})
	}

	return filterQuerys
}

type SortQuery struct {
	Field    string
	Operator string // asc or desc
}

func GetSortQuery(ctx Context) []SortQuery {
	// get all query params, which start with filterQuery
	query := ctx.QueryParams()
	sortQuerys := []SortQuery{}
	for key := range query {
		if !strings.HasPrefix(key, "sort") {
			continue
		}

		// get the value
		operator := query.Get(key)
		// extract the field and operator from the key
		// it looks like this: sort[cve.cvss]=desc

		// remove the filterQuery prefix
		key = strings.TrimPrefix(key, "sort")
		// use a regex
		// get the field
		field := strings.Split(key, "[")[1]
		field = strings.TrimSuffix(field, "]")

		sortQuerys = append(sortQuerys, SortQuery{
			Field:    field,
			Operator: operator,
		})
	}

	return sortQuerys
}

func quoteFields(field string) string {
	// split at the dot
	split := strings.Split(field, ".")
	quotedSplits := utils.Map(
		split,
		func(s string) string {
			return fmt.Sprintf(`"%s"`, s)
		},
	)

	return strings.Join(quotedSplits, ".")
}

// Regular expression to validate field names
var validFieldNameRegex = regexp.MustCompile("^[a-zA-Z0-9_.]+$")

func sanitizeField(field string) string {
	if !validFieldNameRegex.MatchString(field) {
		panic("invalid field name - to risky, might be sql injection")
	}

	return quoteFields(field)
}

func (f FilterQuery) SQL() string {

	field := sanitizeField(f.field)

	switch f.operator {
	case "is":
		return field + " = ?"
	case "is not":
		return field + " != ?"
	case "is greater than":
		return field + " > ?"
	case "is less than":
		return field + " < ?"
	case "is after":
		return field + " > ?"
	case "is before":
		return field + " < ?"
	case "like":
		return field + " LIKE ?"
	case "any":
		return "? = ANY(string_to_array(" + field + ", ' '))"
	default:
		// default do an equals
		return f.field + " = ?"
	}

}

func (f FilterQuery) Value() any {
	// convert the value to the correct type
	switch f.operator {
	case "like":
		return "%" + f.value + "%"
	default:
		return f.value
	}
}

func (s SortQuery) SQL() string {
	// Regular expression to validate field names
	validFieldNameRegex := regexp.MustCompile("^[a-zA-Z0-9_.]+$")

	if !validFieldNameRegex.MatchString(s.Field) {
		panic("invalid field name - to risky, might be sql injection")
	}

	field := sanitizeField(s.Field)

	switch s.Operator {
	case "asc":
		return field + " asc"
	case "desc":
		return field + " desc NULLS LAST"
	default:
		// default do an equals
		return s.Field + " asc NULLS LAST"
	}
}

func (s SortQuery) GetField() string {
	return sanitizeField(s.Field)
}

type Environmental struct {
	ConfidentialityRequirements string
	IntegrityRequirements       string
	AvailabilityRequirements    string
}

func GetEnvironmental(ctx Context) Environmental {
	env := Environmental{
		ConfidentialityRequirements: ctx.QueryParam("confidentialityRequirements"),
		IntegrityRequirements:       ctx.QueryParam("integrityRequirements"),
		AvailabilityRequirements:    ctx.QueryParam("availabilityRequirements"),
	}
	return SanitizeEnv(env)
}

func SanitizeEnv(env Environmental) Environmental {

	replacements := map[string]string{
		"high":   "H",
		"medium": "M",
		"low":    "L",
	}

	replaceValue := func(value string) string {
		if newValue, exists := replacements[value]; exists {
			return newValue
		}
		return value
	}

	env.ConfidentialityRequirements = replaceValue(env.ConfidentialityRequirements)
	env.IntegrityRequirements = replaceValue(env.IntegrityRequirements)
	env.AvailabilityRequirements = replaceValue(env.AvailabilityRequirements)

	return env
}

type BadgeValues struct {
	Key   string
	Value int
	Color string
}

func GetBadgeSVG(label string, values []BadgeValues) string {
	labelWidth := 40
	boxWidth := 25
	boxHeight := 20

	if len(values) == 1 {
		boxWidth = 60 // Adjusted width for single value
	}

	totalWidth := labelWidth + len(values)*boxWidth

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" role="img" aria-label="%s">`,
		totalWidth, boxHeight, label,
	))

	sb.WriteString(fmt.Sprintf(`
<linearGradient id="s" x2="0" y2="100%%">
	<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
	<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<clipPath id="r"><rect width="%d" height="%d" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">`, totalWidth, boxHeight))

	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="#000"/>`, labelWidth, boxHeight))

	for i, val := range values {
		x := labelWidth + i*boxWidth
		sb.WriteString(fmt.Sprintf(`<rect x="%d" width="%d" height="%d" fill="%s"/>`, x, boxWidth, boxHeight, val.Color))
	}

	sb.WriteString(fmt.Sprintf(`<rect width="%d" height="%d" fill="url(#s)"/>`, totalWidth, boxHeight))
	sb.WriteString(`</g>`)

	sb.WriteString(`<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">`)
	sb.WriteString(fmt.Sprintf(`<text x="4" y="14">%s</text>`, label))

	for i, val := range values {
		x := labelWidth + i*boxWidth + 3
		// if there is only one value, just show the key, it's unknown or all clear
		content := val.Key
		if len(values) > 1 {
			// If there are multiple values, show the value next to the key
			content = fmt.Sprintf(`%s:%d`, val.Key, val.Value)
		}
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="14">%s</text>`, x, content))
	}

	sb.WriteString(`</g></svg>`)

	return sb.String()
}

func GoroutineSafeContext(c Context) Context {
	// create a new context - with only the values
	ctx := echohttp.E.NewContext(nil, httptest.NewRecorder())

	// copy all values from the original context that might be needed in goroutines
	if thirdParty, ok := c.Get("thirdPartyIntegration").(IntegrationAggregate); ok {
		ctx.Set("thirdPartyIntegration", thirdParty)
	}

	if session, ok := c.Get("session").(AuthSession); ok {
		ctx.Set("session", session)
	}

	if org, ok := c.Get("organization").(models.Org); ok {
		ctx.Set("organization", org)
	}

	if project, ok := c.Get("project").(models.Project); ok {
		ctx.Set("project", project)
	}

	if asset, ok := c.Get("asset").(models.Asset); ok {
		ctx.Set("asset", asset)
	}

	if assetVersion, ok := c.Get("assetVersion").(models.AssetVersion); ok {
		ctx.Set("assetVersion", assetVersion)
	}

	if rbac, ok := c.Get("rbac").(AccessControl); ok {
		ctx.Set("rbac", rbac)
	}

	if authClient, ok := c.Get("authAdminClient").(AdminClient); ok {
		ctx.Set("authAdminClient", authClient)
	}

	// Copy string values that might be needed
	if orgSlug, ok := c.Get("orgSlug").(string); ok {
		ctx.Set("orgSlug", orgSlug)
	}

	if projectSlug, ok := c.Get("projectSlug").(string); ok {
		ctx.Set("projectSlug", projectSlug)
	}

	if assetSlug, ok := c.Get("assetSlug").(string); ok {
		ctx.Set("assetSlug", assetSlug)
	}

	// Copy public request flag
	if c.Get("publicRequest") != nil {
		ctx.Set("publicRequest", true)
	}

	return ctx
}
