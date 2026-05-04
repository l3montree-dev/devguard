package vulndb

import (
	"github.com/l3montree-dev/devguard/shared"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"
)

var vulndbTracer = otel.Tracer("devguard/vulndb")

var Module = fx.Module("vulndb",
	fx.Provide(fx.Annotate(NewImportService, fx.As(new(shared.VulnDBImportService)))),
)
