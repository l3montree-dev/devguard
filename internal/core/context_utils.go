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

func GetApplicationSlug(c Context) (string, error) {
	applicationSlug := c.Param("applicationSlug")
	if applicationSlug == "" {
		return "", fmt.Errorf("could not get application slug")
	}
	return applicationSlug, nil
}

func GetApplication(c Context) HasID {
	return c.Get("application").(HasID)
}

func GetProject(c Context) HasID {
	return c.Get("project").(HasID)
}

func GetEnv(c Context) HasID {
	return c.Get("env").(HasID)
}

func GetEnvSlug(c Context) (string, error) {
	envSlug := c.Param("envSlug")
	if envSlug == "" {
		return "", fmt.Errorf("could not get env slug")
	}
	return strings.TrimSpace(envSlug), nil
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
