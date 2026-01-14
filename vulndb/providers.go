package vulndb

import (
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

var Module = fx.Module("vulndb",
	fx.Provide(fx.Annotate(NewImportService, fx.As(new(shared.VulnDBImportService)))),
)
