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

func NewDependencyProxyRouter(
	apiV1Group APIV1Router,
	controller *dependencyfirewall.DependencyProxyController,
) DependencyProxyRouter {
	group := apiV1Group.Group.Group("/dependency-proxy")

	// NPM tarballs: unscoped (lodash/-/lodash-4.17.21.tgz) and scoped (@babel/core/-/@babel/core-7.0.0.tgz)
	group.GET("/npm/:package/-/*", controller.ProxyNPMTarball)
	group.GET("/npm/:scope/:name/-/*", controller.ProxyNPMTarball)
	// NPM metadata: unscoped (lodash) and scoped (@babel/core)
	group.GET("/npm/:package", controller.ProxyNPMMetadata)
	group.GET("/npm/:scope/:name", controller.ProxyNPMMetadata)
	// NPM audit
	group.POST("/npm/*", controller.ProxyNPMAudit)

	// Go proxy - handles /dependency-proxy/go/*
	group.GET("/go", controller.ProxyGo)
	group.GET("/go/*", controller.ProxyGo)

	// PyPI simple index (metadata)
	group.GET("/pypi/simple/:package", controller.ProxyPyPISimple)
	group.GET("/pypi/simple/:package/", controller.ProxyPyPISimple)
	// PyPI package downloads
	group.GET("/pypi/packages/*", controller.ProxyPyPIPackage)

	// Secret-scoped routes (used without DevGuard authentication)
	secretGroup := group.Group("/:secret")

	// NPM proxy
	secretGroup.GET("/npm/:package/-/*", controller.ProxyNPMTarball)
	secretGroup.GET("/npm/:scope/:name/-/*", controller.ProxyNPMTarball)
	secretGroup.GET("/npm/:package", controller.ProxyNPMMetadata)
	secretGroup.GET("/npm/:scope/:name", controller.ProxyNPMMetadata)
	secretGroup.POST("/npm/*", controller.ProxyNPMAudit)

	// Golang Proxy
	secretGroup.GET("/go", controller.ProxyGo)
	secretGroup.GET("/go/*", controller.ProxyGo)

	// PYTHON Proxy
	secretGroup.GET("/pypi/simple/:package", controller.ProxyPyPISimple)
	secretGroup.GET("/pypi/simple/:package/", controller.ProxyPyPISimple)
	secretGroup.GET("/pypi/packages/*", controller.ProxyPyPIPackage)

	return DependencyProxyRouter{Group: group}
}
