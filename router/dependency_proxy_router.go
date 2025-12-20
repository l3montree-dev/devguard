// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/labstack/echo/v4"
)

type DependencyProxyRouter struct {
	*echo.Group
}

func NewDependencyProxyRouter(
	apiV1Group APIV1Router,
	controller *controllers.DependencyProxyController,
) DependencyProxyRouter {
	group := apiV1Group.Group.Group("/dependency-proxy")

	// NPM proxy - handles /dependency-proxy/npm/*
	group.GET("/npm", controller.ProxyNPM)
	group.GET("/npm/*", controller.ProxyNPM)

	// Go proxy - handles /dependency-proxy/go/*
	group.GET("/go", controller.ProxyGo)
	group.GET("/go/*", controller.ProxyGo)

	// PyPI proxy - handles /dependency-proxy/pypi/*
	group.GET("/pypi", controller.ProxyPyPI)
	group.GET("/pypi/*", controller.ProxyPyPI)

	return DependencyProxyRouter{Group: group}
}
