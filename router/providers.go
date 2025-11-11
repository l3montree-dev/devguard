package router

import "go.uber.org/fx"

var RouterModule = fx.Options(
	fx.Provide(NewAPIV1Router),
)
