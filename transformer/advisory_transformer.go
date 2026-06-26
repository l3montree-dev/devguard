package transformer

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func AdvisoryCreateRequestToModel(c dtos.AdvisoryCreate) models.Advisory {

	components := make([]models.AffectedPackage, len(c.AffectedPackages))
	for i, asset := range c.AffectedPackages {
		components[i] = AffectedPackageToModel(asset)
	}

	return models.Advisory{
		Title:            c.Title,
		Description:      c.Description,
		AffectedPackages: components,
		Severity:         c.Severity,
		VectorString:     c.VectorString,
		AssetID:          c.AssetID,
	}
}

func AdvisoryUpdateRequestToModel(c dtos.AdvisoryUpdate, advisory models.Advisory) models.Advisory {
	if c.Title != nil {
		advisory.Title = *c.Title
	}
	if c.Description != nil {
		advisory.Description = *c.Description
	}
	if c.Severity != nil {
		advisory.Severity = *c.Severity
	}
	if c.VectorString != nil {
		advisory.VectorString = *c.VectorString
	}
	if c.AffectedPackages != nil {
		components := make([]models.AffectedPackage, len(c.AffectedPackages))
		for i, asset := range c.AffectedPackages {
			components[i] = AffectedPackageToModel(asset)
		}
		advisory.AffectedPackages = components
	}
	if c.AssetID != nil {
		advisory.AssetID = *c.AssetID
	}
	return advisory
}

func AffectedPackageToModel(c dtos.AffectedPackage) models.AffectedPackage {
	return models.AffectedPackage{
		Model:            models.Model{ID: c.ID},
		Ecosystem:        c.Ecosystem,
		PackageName:      c.PackageName,
		SemverIntroduced: c.SemverIntroduced,
		SemverFixed:      c.SemverFixed,
	}
}
