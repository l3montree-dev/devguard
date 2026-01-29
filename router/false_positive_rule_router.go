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

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/labstack/echo/v4"
)

type FalsePositiveRuleRouter struct {
	*echo.Group
}

func NewFalsePositiveRuleRouter(
	assetRouter AssetRouter,
	falsePositiveRuleController *controllers.FalsePositiveRuleController,
) FalsePositiveRuleRouter {
	// False positive rules are scoped to assets
	// Read access - anyone who can read the asset can list rules
	ruleGroup := assetRouter.Group.Group("/false-positive-rules")
	ruleGroup.GET("/", falsePositiveRuleController.List)
	ruleGroup.GET("/:ruleId/", falsePositiveRuleController.Get)

	// Write access - requires asset update permission
	ruleWriteGroup := ruleGroup.Group("", middlewares.NeededScope([]string{"manage"}))
	ruleWriteGroup.POST("/", falsePositiveRuleController.Create)
	ruleWriteGroup.PUT("/:ruleId/", falsePositiveRuleController.Update)
	ruleWriteGroup.DELETE("/:ruleId/", falsePositiveRuleController.Delete)

	return FalsePositiveRuleRouter{Group: ruleGroup}
}
