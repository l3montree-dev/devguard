package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/ory/client-go"
	"gorm.io/gorm"
)

type AdminService struct {
	casbinRBACProvider   shared.RBACProvider
	orgRepository        shared.OrganizationRepository
	statisticsRepository shared.StatisticsRepository
}

func NewAdminService(casbinRBACProvider shared.RBACProvider, orgRepository shared.OrganizationRepository, statisticsRepository shared.StatisticsRepository) *AdminService {
	return &AdminService{casbinRBACProvider: casbinRBACProvider, orgRepository: orgRepository, statisticsRepository: statisticsRepository}
}

func (service AdminService) GetAdminsForOrg(ctx context.Context, orgID uuid.UUID, adminClient shared.AdminClient) ([]dtos.UserDTO, error) {
	orgRBAC := service.casbinRBACProvider.GetDomainRBAC(orgID.String())
	adminIDs, err := orgRBAC.GetAdminsOfOrganization()
	if err != nil {
		return nil, err
	}

	if len(adminIDs) == 0 {
		return []dtos.UserDTO{}, nil
	}

	memberIdentities, err := adminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(adminIDs))
	if err != nil {
		return nil, err
	}
	users := make([]dtos.UserDTO, 0, len(adminIDs))
	for _, member := range memberIdentities {
		users = append(users, dtos.UserDTO{
			ID:   member.Id,
			Name: shared.IdentityName(member.Traits),
			Role: string(shared.RoleAdmin),
		})
	}

	return users, nil
}

func (service AdminService) GetUserIDFromMail(ctx context.Context, adminClient shared.AdminClient, email string) (uuid.UUID, error) {
	allUsers, err := adminClient.ListUser(client.IdentityAPIListIdentitiesRequest{})
	if err != nil {
		return uuid.UUID{}, err
	}

	usersWithRequestedMail := make([]client.Identity, 0, 1)
	for _, user := range allUsers {
		userMail := shared.IdentityEmail(user.Traits)
		if userMail != "" && userMail == email {
			usersWithRequestedMail = append(usersWithRequestedMail, user)
		}
	}

	switch len(usersWithRequestedMail) {
	case 0:
		return uuid.UUID{}, dtos.ErrCouldNotFindUserWithMail
	case 1:
		return uuid.Parse(usersWithRequestedMail[0].Id)
	default:
		return uuid.UUID{}, dtos.ErrCouldNotFindDefinitiveUserWithMail
	}
}

func (service AdminService) GetMailFromUserID(ctx context.Context, authClient shared.AdminClient, userID uuid.UUID) (string, error) {
	userIdentity, err := authClient.GetIdentity(ctx, userID.String())
	if err != nil {
		return "", err
	}
	email := shared.IdentityEmail(userIdentity.Traits)
	if email == "" {
		return "", fmt.Errorf("could not find mail for user")
	}
	return email, nil
}

func (service AdminService) AddAdminToOrg(ctx context.Context, orgID uuid.UUID, userID uuid.UUID) error {
	// create a fake session for the user to grant the role in the org domain
	fakeSession := shared.NewSession(userID.String(), shared.SessionActorUser, []string{}, false)
	return service.casbinRBACProvider.GetDomainRBAC(orgID.String()).GrantRole(ctx, fakeSession, "admin")
}

func (service AdminService) RevokeAdminFromOrg(ctx context.Context, orgID uuid.UUID, userID uuid.UUID) error {
	// create a fake session for the user to grant the role in the org domain
	fakeSession := shared.NewSession(userID.String(), shared.SessionActorUser, []string{}, false)
	return service.casbinRBACProvider.GetDomainRBAC(orgID.String()).RevokeRole(ctx, fakeSession, "admin")
}

func (service AdminService) CheckIfOrgExists(ctx context.Context, orgID uuid.UUID) error {
	_, err := service.orgRepository.Read(ctx, nil, orgID)
	return err
}

func (service AdminService) GetOwnerForOrg(ctx context.Context, orgID uuid.UUID) (uuid.UUID, error) {
	owner, err := service.casbinRBACProvider.GetDomainRBAC(orgID.String()).GetOwnerOfOrganization()
	if err != nil {
		return uuid.UUID{}, err
	}
	return uuid.Parse(owner)
}

func (service AdminService) GetOrgsWhereUserIsOwner(ctx context.Context, userID uuid.UUID) ([]models.Org, error) {
	domains, err := service.casbinRBACProvider.GetOwnerDomainsOfUser(userID.String())
	if err != nil {
		return nil, err
	}

	parsedOrgIDs := make([]uuid.UUID, 0, len(domains))
	for _, domain := range domains {
		parsedDomainID, err := uuid.Parse(domain)
		if err != nil {
			return nil, err
		}
		parsedOrgIDs = append(parsedOrgIDs, parsedDomainID)
	}

	orgs, err := service.orgRepository.List(ctx, nil, parsedOrgIDs)
	if err != nil {
		return nil, err
	}

	return orgs, nil
}

func (service AdminService) GetInstanceUsageStatistics(ctx context.Context, tx *gorm.DB, authClient shared.AdminClient) (dtos.InstanceUsageStatistics, error) {
	instanceStatistics, err := service.statisticsRepository.GetInstanceUsageStatistics(ctx, tx)
	if err != nil {
		return dtos.InstanceUsageStatistics{}, fmt.Errorf("could not calculate usage statistics from database: %w", err)
	}

	users, err := authClient.ListUser(client.IdentityAPIListIdentitiesRequest{})
	if err != nil {
		return dtos.InstanceUsageStatistics{}, fmt.Errorf("could not list users from oras: %w", err)
	}
	instanceStatistics.NumberOfUsers = len(users)
	return instanceStatistics, nil
}

func (service AdminService) GetInstanceVulnStatistics(ctx context.Context, topCVEsLimit, topComponentsLimit, topProjectsLimit int) (dtos.InstanceOverview, error) {
	res := utils.Concurrently(
		func() (any, error) { // 0: topCVEs
			results, err := service.statisticsRepository.GetTopCVEsAcrossInstance(ctx, nil, topCVEsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get top CVEs across instance: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 1: topComponents
			results, err := service.statisticsRepository.GetTopComponentsAcrossInstance(ctx, nil, topComponentsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get top components across instance: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 2: maliciousPackages
			results, err := service.statisticsRepository.FindMaliciousPackagesAcrossInstance(ctx, nil)
			if err != nil {
				return results, fmt.Errorf("could not get malicious packages across instance: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 3: averageOpenCodeRisks
			results, err := service.statisticsRepository.GetAvgOpenCodeRisksAcrossInstance(ctx, nil)
			if err != nil {
				return results, fmt.Errorf("could not get average open code risks across instance: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 4: topVulnerableProjects
			results, err := service.statisticsRepository.GetMostVulnerableProjectsAcrossInstance(ctx, nil, topProjectsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most vulnerable projects across instance: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 5: averageOpenVulnsPerOrg
			results, err := service.statisticsRepository.GetAverageOpenVulnsPerOrgAcrossInstance(ctx, nil)
			if err != nil {
				return results, fmt.Errorf("could not get average open vulns per org across instance: %w", err)
			}
			return results, nil
		},
	)

	if res.HasErrors() {
		slog.Error("could not get instance statistics", "errors", res.Errors())
		return dtos.InstanceOverview{}, fmt.Errorf("could not get instance statistics")
	}

	return dtos.InstanceOverview{
		TopCVEs:                res.GetValue(0).([]dtos.CVEOccurrence),
		TopComponents:          res.GetValue(1).([]dtos.ComponentOccurrenceAcrossInstance),
		MaliciousPackages:      res.GetValue(2).([]dtos.MaliciousPackage),
		AverageOpenCodeRisks:   res.GetValue(3).(float32),
		TopVulnerableProjects:  res.GetValue(4).([]dtos.ProjectVulnDistribution),
		AverageOpenVulnsPerOrg: res.GetValue(5).(dtos.OrgVulnAverage),
	}, nil
}
