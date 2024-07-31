package vulndb

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

type cveRepository interface {
	repositories.Repository[string, models.CVE, database.DB]
	FindByID(id string) (models.CVE, error)
	GetLastModDate() (time.Time, error)
	SaveBatchCPEMatch(tx database.DB, matches []models.CPEMatch) error
}

type configService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type leaderElector interface {
	IsLeader() bool
}

func StartMirror(database core.DB, leaderElector leaderElector, configService configService) {
	return
	cveRepository := repositories.NewCVERepository(database)
	cweRepository := repositories.NewCWERepository(database)
	affectedCmpRepository := repositories.NewAffectedCmpRepository(database)
	exploitRepository := repositories.NewExploitRepository(database)

	nvdService := NewNVDService(cveRepository)
	epssService := NewEPSSService(nvdService, cveRepository)
	mitreService := NewMitreService(cweRepository)

	exploitDBService := NewExploitDBService(nvdService, exploitRepository)
	githubExploitDBService := NewGithubExploitDBService(exploitRepository)

	osvService := NewOSVService(affectedCmpRepository)

	//for flaw service
	flawRepository := repositories.NewFlawRepository(database)
	flawEventRepository := repositories.NewFlawEventRepository(database)
	assetRepository := repositories.NewAssetRepository(database)
	flawService := flaw.NewService(flawRepository, flawEventRepository, assetRepository, cveRepository)

	// start the mirror process.
	vulnDBService := newVulnDBService(leaderElector, mitreService, epssService, nvdService, configService, osvService, exploitDBService, githubExploitDBService, flawService)

	vulnDBService.startMirrorDaemon()
}
