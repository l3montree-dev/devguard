package dependency_vuln_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
)

func TestCreateIssuesForVulnsIfThresholdExceeded(t *testing.T) {
	t.Run("Both Thresholds set and both CVSS and risk values are provided should return no error", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065",
				State: models.VulnStateOpen,
			},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err != nil {
			t.Fail()
		}
	})
	t.Run("No Thresholds set and both CVSS and risk values are provided should return no error because the user doesn't want automatic tickets", func(t *testing.T) {

		s := dependency_vuln.NewService(nil, nil, nil, nil, nil, nil, nil, nil)

		asset := models.Asset{}

		vuln1 := models.DependencyVuln{}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err != nil {
			t.Fail()
		}
	})
	t.Run("Should fail if projectRepository Read returns an error", func(t *testing.T) {

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, fmt.Errorf("Something went wrong"))

		s := dependency_vuln.NewService(nil, nil, nil, nil, nil, projectRepository, nil, nil)

		asset := models.Asset{
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
		}

		vuln1 := models.DependencyVuln{}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Should fail if orgRepository Read returns an error", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, fmt.Errorf("Something went wrong"))

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, nil, nil)

		asset := models.Asset{
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			// no RepositoryID set
		}

		vuln1 := models.DependencyVuln{}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Should not fail if repository ID cannot be determined because devguard isn't integrated yet", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: ""}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: ""}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			// no RepositoryID set
		}

		vuln1 := models.DependencyVuln{}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err != nil {
			t.Fail()
		}
	})
	t.Run("Both Thresholds set and both CVSS and risk values are provided but the create Issue function returns an error and therefore should fail", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateOpen,
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065", AssetVersionName: "GenieOderWAHNSINN"},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Only CVSS Threshold is provided an both CVSS and risk values are provided", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateOpen,
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065"},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err != nil {
			t.Fail()
		}
	})

	t.Run("Only CVSS Threshold is set and both CVSS and risk values are provided but the create Issue function returns an error and therefore should fail", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateOpen,
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065"},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Only Risk Threshold is set and both CVSS and risk values are provided but the create Issue function returns an error and therefore should fail", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)
		thirdPartyIntegration.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateOpen,
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065"},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err == nil {
			t.Fail()
		}
	})

	t.Run("should reopen the issue, if a vuln already has an assigned ticket", func(t *testing.T) {
		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Read", mock.Anything).Return(models.Org{Slug: "ptest"}, nil)

		projectRepository := mocks.NewProjectRepository(t)
		projectRepository.On("Read", mock.Anything).Return(models.Project{OrganizationID: uuid.MustParse("52cfdc4c-42ee-436f-9a56-66e441e37dcc"), Slug: "projecttest"}, nil)

		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)

		thirdPartyIntegration.On("ReopenIssue", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		s := dependency_vuln.NewService(nil, nil, nil, nil, organizationRepository, projectRepository, thirdPartyIntegration, nil)

		asset := models.Asset{
			CVSSAutomaticTicketThreshold: utils.Ptr(0.),
			RiskAutomaticTicketThreshold: utils.Ptr(0.),
			ProjectID:                    uuid.MustParse("3bf8dfdd-e82b-42ce-9381-17f6f588bc26"),
			RepositoryID:                 utils.Ptr("gitlab:05797bd8-33ac-4bd5-b8ec-e1bb3423dd79:3563"),
		}

		vuln1 := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateOpen,
				ID:    "66ea9a6781904477d8d401dc1a27338187d0502bc7acaed6295cb0b570f11065", AssetVersionName: "GenieOderWAHNSINN",
				TicketID: utils.Ptr("ticket-id"),
			},
			CVE:               &models.CVE{CVSS: 5},
			RawRiskAssessment: utils.Ptr(5.),
		}
		vulns := []models.DependencyVuln{vuln1}

		err := s.CreateIssuesForVulnsIfThresholdExceeded(asset, vulns)
		if err != nil {
			t.Fail()
		}
	})
}

func TestShouldCreateIssue(t *testing.T) {
	t.Run("should return false if the assetVersion is not the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: false,
		}
		s := dependency_vuln.NewService(nil, nil, nil, nil, nil, nil, nil, nil)

		defaultBranch := s.ShouldCreateIssues(assetVersion)
		if defaultBranch {
			t.Fail()
		}
	})
	t.Run("should return true if the assetVersion is the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: true,
		}
		s := dependency_vuln.NewService(nil, nil, nil, nil, nil, nil, nil, nil)

		defaultBranch := s.ShouldCreateIssues(assetVersion)
		if !defaultBranch {
			t.Fail()
		}
	})

}
