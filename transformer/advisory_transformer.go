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
	}
}

func AffectedPackageToModel(c dtos.AffectedPackage) models.AffectedPackage {
	return models.AffectedPackage{
		Ecosystem:        c.Ecosystem,
		PackageName:      c.PackageName,
		SemverIntroduced: c.SemverIntroduced,
		SemverFixed:      c.SemverFixed,
	}
}
