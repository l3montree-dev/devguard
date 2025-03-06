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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/database/models"

	"github.com/ory/client-go"
)

type AuthSession interface {
	GetUserID() string
}

func GetThirdPartyIntegration(c Context) IntegrationAggregate {
	return c.Get("thirdPartyIntegration").(IntegrationAggregate)
}

func SetThirdPartyIntegration(c Context, i IntegrationAggregate) {
	c.Set("thirdPartyIntegration", i)
}

func SetAuthAdminClient(c Context, i *client.APIClient) {
	c.Set("authAdminClient", i)
}

func GetAuthAdminClient(c Context) *client.APIClient {
	return c.Get("authAdminClient").(*client.APIClient)
}

func GetVulnID(c Context) (string, error) {
	dependencyVulnID := c.Param("dependencyVulnId")
	if dependencyVulnID == "" {
		return "", fmt.Errorf("could not get dependencyVuln id")
	}
	return dependencyVulnID, nil
}

func GetRBAC(c Context) accesscontrol.AccessControl {
	return c.Get("rbac").(accesscontrol.AccessControl)
}

func GetTenant(c Context) models.Org {
	return c.Get("tenant").(models.Org)
}

func SetIsPublicRequest(c Context) {
	c.Set("publicRequest", true)
}

func IsPublicRequest(c Context) bool {
	return c.Get("publicRequest") != nil
}

func GetOryClient(c Context) *client.APIClient {
	return c.Get("ory").(*client.APIClient)
}

func GetSession(ctx Context) AuthSession {
	return ctx.Get("session").(AuthSession)
}

func SetSession(ctx Context, session AuthSession) {
	ctx.Set("session", session)
}

func GetParam(c Context, param string) string {
	v := c.Param(param)
	if v == "" {
		fallback := c.Get(param)
		if fallback == nil {
			return ""
		}
		return fallback.(string)
	}
	return v
}

func GetProjectSlug(c Context) (string, error) {
	projectID := GetParam(c, "projectSlug")
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetOrgSlug(c Context) (string, error) {
	orgSlug := GetParam(c, "orgSlug")
	if orgSlug == "" {
		return "", fmt.Errorf("could not get org slug")
	}
	return orgSlug, nil
}

func SetOrgSlug(c Context, orgSlug string) {
	c.Set("orgSlug", orgSlug)
}

func SetProjectSlug(c Context, projectSlug string) {
	c.Set("projectSlug", projectSlug)
}

func SetAssetSlug(c Context, assetSlug string) {
	c.Set("assetSlug", assetSlug)
}

func GetAssetSlug(c Context) (string, error) {
	assetSlug := GetParam(c, "assetSlug")
	if assetSlug == "" {
		return "", fmt.Errorf("could not get asset slug")
	}
	return assetSlug, nil
}

func GetAssetVersionSlug(c Context) (string, error) {
	assetVersionSlug := GetParam(c, "assetVersionSlug")
	if assetVersionSlug == "" {
		return "", fmt.Errorf("could not get asset version slug")
	}
	return assetVersionSlug, nil
}

func GetAsset(c Context) models.Asset {
	return c.Get("asset").(models.Asset)
}

func SetAsset(c Context, asset models.Asset) {
	c.Set("asset", asset)
}

func GetAssetVersion(c Context) models.AssetVersion {
	return c.Get("assetVersion").(models.AssetVersion)
}

func SetAssetVersion(c Context, assetVersion models.AssetVersion) {
	c.Set("assetVersion", assetVersion)
}

func SetProject(c Context, project models.Project) {
	c.Set("project", project)
}

func GetProject(c Context) models.Project {
	return c.Get("project").(models.Project)
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

func GetRepositoryID(c Context) (string, error) {
	// get the asset
	asset := GetAsset(c)
	// get the project
	project := GetProject(c)
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

func field2TableName(fieldName string) string {
	switch fieldName {
	case "cve":
		return "CVE"
	default:
		return fieldName
	}
}

func quoteRelationField(field string) string {
	// split at the dot
	split := strings.Split(field, ".")
	if len(split) > 1 {
		// quote the field. it looks like this: "cve"."cvss"
		return fmt.Sprintf("\"%s\".\"%s\"", field2TableName(split[0]), split[1])
	}
	return field
}

var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

// Regular expression to validate field names
var validFieldNameRegex = regexp.MustCompile("^[a-zA-Z0-9_.]+$")

func toSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func sanitizeField(field string) string {
	if !validFieldNameRegex.MatchString(field) {
		panic("invalid field name - to risky, might be sql injection")
	}

	return quoteRelationField(toSnakeCase(field))
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
