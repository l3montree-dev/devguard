// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"github.com/l3montree-dev/devguard/controllers/dependencyfirewall"
	"github.com/labstack/echo/v4"
)

type DependencyProxyRouter struct {
	*echo.Group
}

func registerNPMRoutes(group *echo.Group, npmController *dependencyfirewall.NPMDependencyProxyController) {
	// NPM tarballs: unscoped (lodash/-/lodash-4.17.21.tgz) and scoped (@babel/core/-/@babel/core-7.0.0.tgz)
	group.GET("/npm/:package/-/*", npmController.ProxyNPMTarball)
	group.GET("/npm/:scope/:name/-/*", npmController.ProxyNPMTarball)
	// NPM metadata: unscoped (lodash) and scoped (@babel/core)
	group.GET("/npm/:package", npmController.ProxyNPMMetadata)
	group.GET("/npm/:scope/:name", npmController.ProxyNPMMetadata)
	// NPM audit
	group.POST("/npm/*", npmController.ProxyNPMAudit)
}

func registerGoRoutes(group *echo.Group, goController *dependencyfirewall.GoDependencyProxyController) {
	// Go proxy - handles /dependency-proxy/go/*
	group.GET("/go", goController.ProxyGo)
	group.GET("/go/*", goController.ProxyGo)
}

func registerPyPIRoutes(group *echo.Group, pythonController *dependencyfirewall.PythonDependencyProxyController) {
	// PyPI simple index (metadata)
	group.GET("/pypi/simple/:package", pythonController.ProxyPyPISimple)
	group.GET("/pypi/simple/:package/", pythonController.ProxyPyPISimple)
	// PyPI package downloads
	group.GET("/pypi/packages/*", pythonController.ProxyPyPIPackage)
}

func NewDependencyProxyRouter(
	apiV1Group APIV1Router,
	npmController *dependencyfirewall.NPMDependencyProxyController,
	goController *dependencyfirewall.GoDependencyProxyController,
	pythonController *dependencyfirewall.PythonDependencyProxyController,
) DependencyProxyRouter {
	group := apiV1Group.Group.Group("/dependency-proxy")

	registerNPMRoutes(group, npmController)
	registerGoRoutes(group, goController)
	registerPyPIRoutes(group, pythonController)

	// Secret-scoped routes (used without DevGuard authentication)
	secretGroup := group.Group("/:secret")

	registerNPMRoutes(secretGroup, npmController)
	registerGoRoutes(secretGroup, goController)
	registerPyPIRoutes(secretGroup, pythonController)

	return DependencyProxyRouter{Group: group}
}
