package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/ory/client-go"
)

type AdminService struct {
	casbinRBACProvider shared.RBACProvider
	orgRepository      shared.OrganizationRepository
}

func NewAdminService(casbinRBACProvider shared.RBACProvider, orgRepository shared.OrganizationRepository) *AdminService {
	return &AdminService{casbinRBACProvider: casbinRBACProvider, orgRepository: orgRepository}
}

func (service AdminService) GetAdminsForOrg(orgID uuid.UUID, adminClient shared.AdminClient) ([]dtos.UserDTO, error) {
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
		return uuid.UUID{}, fmt.Errorf(dtos.ErrorCouldNotFindUserWithMail)
	case 1:
		return uuid.Parse(usersWithRequestedMail[0].Id)
	default:
		return uuid.UUID{}, fmt.Errorf(dtos.ErrorCouldNotFindDefinitiveUserWithMail)
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
	return service.casbinRBACProvider.GetDomainRBAC(orgID.String()).GrantRole(ctx, userID.String(), "admin")
}

func (service AdminService) RevokeAdminFromOrg(ctx context.Context, orgID uuid.UUID, userID uuid.UUID) error {
	return service.casbinRBACProvider.GetDomainRBAC(orgID.String()).RevokeRole(ctx, userID.String(), "admin")
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
