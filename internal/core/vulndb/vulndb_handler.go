package vulndb

import (
	"time"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
)

type cveRepository interface {
	repositories.Repository[string, models.CVE, database.DB]
	FindByID(id string) (models.CVE, error)
	GetLastModDate() (time.Time, error)
}

type configService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type leaderElector interface {
	IsLeader() bool
}

func StartMirror(database core.DB, leaderElector leaderElector, configService configService) {
	cveRepository := repositories.NewCVERepository(database)
	cweRepository := repositories.NewCWERepository(database)
	affectedCmpRepository := repositories.NewAffectedCmpRepository(database)

	nvdService := NewNVDService(cveRepository)
	epssService := newEPSSService(nvdService, cveRepository)
	mitreService := newMitreService(leaderElector, cweRepository)

	osvService := newOSVService(affectedCmpRepository)
	// start the mirror process.
	vulnDBService := newVulnDBService(leaderElector, mitreService, epssService, nvdService, configService, osvService)

	vulnDBService.startMirrorDaemon()
}
