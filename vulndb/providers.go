package vulndb

import (
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/shared"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"
)

var vulndbTracer = otel.Tracer("devguard/vulndb")

func provideMaliciousPackageChecker(db shared.DB) (*MaliciousPackageChecker, error) {
	repo := repositories.NewMaliciousPackageRepository(db)
	return NewMaliciousPackageChecker(repo)
}

var Module = fx.Module("vulndb",
	fx.Provide(provideMaliciousPackageChecker),
	fx.Provide(fx.Annotate(NewVulnDBService, fx.As(new(shared.VulnDBService)))),
)
