// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"regexp"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/database/models"
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
	GetIdentity(ctx context.Context, userID string) (client.Identity, error)
}

type adminClientImplementation struct {
	apiClient *client.APIClient
}

func NewAdminClient(client *client.APIClient) adminClientImplementation {
	return adminClientImplementation{
		apiClient: client,
	}
}
func (a adminClientImplementation) ListUser(request client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error) {
	clients, _, err := a.apiClient.IdentityAPI.ListIdentitiesExecute(request)
	return clients, err
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
	dependencyVulnID := ctx.Param("dependencyVulnId")
	if dependencyVulnID != "" {
		return dependencyVulnID, models.VulnTypeDependencyVuln, nil
	}

	dependencyVulnIDFromGet, ok := ctx.Get("dependencyVulnId").(string)
	if ok && dependencyVulnIDFromGet != "" {
		return dependencyVulnIDFromGet, models.VulnTypeDependencyVuln, nil
	}
	firstPartyVulnID := ctx.Param("firstPartyVulnId")
	if firstPartyVulnID != "" {
		return firstPartyVulnID, models.VulnTypeFirstPartyVuln, nil
	}
	firstPartyVulnIDFromGet, ok := ctx.Get("firstPartyVulnId").(string)
	if ok && firstPartyVulnIDFromGet != "" {
		return firstPartyVulnIDFromGet, models.VulnTypeFirstPartyVuln, nil
	}

	return "", "", fmt.Errorf("could not get vuln id")
}

func SetRBAC(ctx Context, rbac accesscontrol.AccessControl) {
	ctx.Set("rbac", rbac)
}

func GetOrganization(c Context) models.Org {
	return c.Get("organization").(models.Org)
}

func HasOrganization(c Context) bool {
	_, ok := c.Get("organization").(models.Org)
	return ok
}

func SetOrganization(c Context, org models.Org) {
	c.Set("organization", org)
}

func GetRBAC(ctx Context) accesscontrol.AccessControl {
	return ctx.Get("rbac").(accesscontrol.AccessControl)
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

func SetOrg(c Context, org models.Org) {
	c.Set("org", org)
}

func SetOrgSlug(ctx Context, orgSlug string) {
	ctx.Set("orgSlug", orgSlug)
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

func RecursiveGetProjectRepositoryID(project models.Project) (string, error) {

	if project.RepositoryID != nil {
		return *project.RepositoryID, nil
	}

	if project.Parent == nil {
		return "", fmt.Errorf("could not get repository id")
	}

	return RecursiveGetProjectRepositoryID(*project.Parent)
}

func GetRepositoryIdFromAssetAndProject(project models.Project, asset models.Asset) (string, error) {
	if asset.RepositoryID != nil {
		return *asset.RepositoryID, nil
	}

	return RecursiveGetProjectRepositoryID(project)
}

func GetRepositoryID(ctx Context) (string, error) {
	// get the asset
	asset := GetAsset(ctx)
	if asset.RepositoryID != nil {
		return *asset.RepositoryID, nil
	}
	// get the project
	project := GetProject(ctx)
	return GetRepositoryIdFromAssetAndProject(project, asset)
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

	if len(values) == 0 {
		values = []BadgeValues{
			{"?", 0, "#808080"},
		}
		boxWidth = 60 // Adjusted width for the "unknown" box
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
		content := fmt.Sprintf(`%s:%d`, val.Key, val.Value)
		if val.Key == "?" {
			content = "unknown"
		}
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="14">%s</text>`, x, content))
	}

	sb.WriteString(`</g></svg>`)

	return sb.String()
}
