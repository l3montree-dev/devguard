package transformer

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func currentScope(projectID, assetID *uuid.UUID) dtos.SecretScope {
	if assetID != nil {
		return dtos.ScopeAsset
	}
	if projectID != nil {
		return dtos.ScopeProject
	}
	return dtos.ScopeOrganization
}

func SecretToDTO(secret models.Secret, inheritedFrom *string) dtos.SecretDTO {
	return dtos.SecretDTO{
		ID:            secret.ID,
		Name:          secret.Name,
		Scope:         currentScope(secret.ProjectID, secret.AssetID),
		InheritedFrom: inheritedFrom,
		Value:         secret.Value,
	}
}
