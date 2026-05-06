package services

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/ory/client-go"
)

type AdminService struct {
	casbinRBACProvider shared.RBACProvider
}

func NewAdminService(casbinRBACProvider shared.RBACProvider) *AdminService {
	return &AdminService{casbinRBACProvider: casbinRBACProvider}
}

func (service AdminService) GetAdminsForOrg(orgID uuid.UUID, adminClient shared.AdminClient) ([]dtos.UserDTO, error) {
	orgRBAC := service.casbinRBACProvider.GetDomainRBAC(orgID.String())
	adminIDs := orgRBAC.GetAdminsOfOrganization()

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
