package services

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type service struct {
	releaseRepository shared.ReleaseRepository
}

func NewService(releaseRepository shared.ReleaseRepository) *service {
	return &service{
		releaseRepository: releaseRepository,
	}
}

func (s *service) ListByProject(projectID uuid.UUID) ([]models.Release, error) {
	return s.releaseRepository.GetByProjectID(projectID)
}

func (s *service) ListByProjectPaged(projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.Release], error) {
	return s.releaseRepository.GetByProjectIDPaged(nil, projectID, pageInfo, search, filter, sort)
}

func (s *service) Read(id uuid.UUID) (models.Release, error) {
	return s.releaseRepository.Read(id)
}

// ReadRecursive returns the release and recursively loads child releases (by ReleaseItem.ChildReleaseID).
// It protects against cycles by tracking visited IDs.
func (s *service) ReadRecursive(id uuid.UUID) (models.Release, error) {
	return s.releaseRepository.ReadRecursive(id)
}

func (s *service) Create(r *models.Release) error {
	return s.releaseRepository.Create(nil, r)
}

func (s *service) Update(r *models.Release) error {
	return s.releaseRepository.Save(nil, r)
}

func (s *service) Delete(id uuid.UUID) error {
	return s.releaseRepository.Delete(nil, id)
}

// AddItem creates a ReleaseItem linking an artifact or child release to a release.
func (s *service) AddItem(item *models.ReleaseItem) error {
	return s.releaseRepository.CreateReleaseItem(nil, item)
}

// RemoveItem deletes the ReleaseItem with the given id.
func (s *service) RemoveItem(id uuid.UUID) error {
	return s.releaseRepository.DeleteReleaseItem(nil, id)
}

// ListCandidates returns artifact and release candidates for a given release (project scoped)
func (s *service) ListCandidates(projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error) {
	return s.releaseRepository.GetCandidateItemsForRelease(projectID, releaseID)
}
