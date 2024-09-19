package vulndb

type flawService interface {
	RecalculateAllRawRiskAssessments() error
}

type vulnDBService struct {
	leaderElector leaderElector

	mitreService           mitreService
	epssService            epssService
	nvdService             NVDService
	osvService             osvService
	exploitDBService       exploitDBService
	githubExploitDBService githubExploitDBService
	dsa                    debianSecurityTracker
	cveList                cvelistService

	configService configService

	flawService flawService
}

func newVulnDBService(leaderElector leaderElector, mitreService mitreService, epssService epssService, nvdService NVDService, configService configService, osvService osvService, exploitDBService exploitDBService, githubExploitDBService githubExploitDBService, flawService flawService, dsa debianSecurityTracker, cveList cvelistService) *vulnDBService {
	return &vulnDBService{
		leaderElector: leaderElector,
		// Add a comma after leaderElector
		osvService:             osvService,
		mitreService:           mitreService,
		epssService:            epssService,
		nvdService:             nvdService,
		exploitDBService:       exploitDBService,
		githubExploitDBService: githubExploitDBService,
		dsa:                    dsa,
		cveList:                cveList,

		configService: configService,

		flawService: flawService,
	}
}
