// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type artifactRepository struct {
	common.Repository[string, models.Artifact, core.DB]
	db core.DB
}

func NewArtifactRepository(db core.DB) *artifactRepository {
	return &artifactRepository{
		db:         db,
		Repository: newGormRepository[string, models.Artifact](db),
	}
}
