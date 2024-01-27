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

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
)

type HasID interface {
	GetID() uuid.UUID
}

type Tenant interface {
	GetID() uuid.UUID
}

func GetFlawID(c Context) (uuid.UUID, error) {
	flawID := c.Param("flawId")
	if flawID == "" {
		return uuid.UUID{}, fmt.Errorf("could not get flaw id")
	}
	return uuid.Parse(flawID)
}

func GetRBAC(c Context) accesscontrol.AccessControl {
	return c.Get("rbac").(accesscontrol.AccessControl)
}

func GetTenant(c Context) Tenant {
	return c.Get("tenant").(Tenant)
}

func GetSession(ctx Context) auth.AuthSession {
	return ctx.Get("session").(auth.AuthSession)
}

func GetProjectSlug(c Context) (string, error) {
	projectID := c.Param("projectSlug")
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetAssetSlug(c Context) (string, error) {
	assetSlug := c.Param("assetSlug")
	if assetSlug == "" {
		return "", fmt.Errorf("could not get asset slug")
	}
	return assetSlug, nil
}

func GetAsset(c Context) HasID {
	return c.Get("asset").(HasID)
}

func GetProject(c Context) HasID {
	return c.Get("project").(HasID)
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
	Field    string
	Value    string
	Operator string
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

		fmt.Println(field, operator, value)

		filterQuerys = append(filterQuerys, FilterQuery{
			Field:    field,
			Value:    value,
			Operator: operator,
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

	field := sanitizeField(f.Field)

	switch f.Operator {
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
	default:
		// default do an equals
		return f.Field + " = ?"
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
		return field + " desc"
	default:
		// default do an equals
		return s.Field + " asc"
	}
}
