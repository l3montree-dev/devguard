package services

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type releaseService struct {
	releaseRepository shared.ReleaseRepository
}

func NewReleaseService(releaseRepository shared.ReleaseRepository) *releaseService {
	return &releaseService{
		releaseRepository: releaseRepository,
	}
}

func (s *releaseService) ListByProject(projectID uuid.UUID) ([]models.Release, error) {
	return s.releaseRepository.GetByProjectID(projectID)
}

func (s *releaseService) ListByProjectPaged(projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.Release], error) {
	return s.releaseRepository.GetByProjectIDPaged(nil, projectID, pageInfo, search, filter, sort)
}

func (s *releaseService) Read(id uuid.UUID) (models.Release, error) {
	return s.releaseRepository.Read(id)
}

// ReadRecursive returns the release and recursively loads child releases (by ReleaseItem.ChildReleaseID).
// It protects against cycles by tracking visited IDs.
func (s *releaseService) ReadRecursive(id uuid.UUID) (models.Release, error) {
	return s.releaseRepository.ReadRecursive(id)
}

func (s *releaseService) Create(r *models.Release) error {
	return s.releaseRepository.Create(nil, r)
}

func (s *releaseService) Update(r *models.Release) error {
	return s.releaseRepository.Save(nil, r)
}

func (s *releaseService) Delete(id uuid.UUID) error {
	return s.releaseRepository.Delete(nil, id)
}

// AddItem creates a ReleaseItem linking an artifact or child release to a release.
func (s *releaseService) AddItem(item *models.ReleaseItem) error {
	return s.releaseRepository.CreateReleaseItem(nil, item)
}

// RemoveItem deletes the ReleaseItem with the given id.
func (s *releaseService) RemoveItem(id uuid.UUID) error {
	return s.releaseRepository.DeleteReleaseItem(nil, id)
}

// ListCandidates returns artifact and release candidates for a given release (project scoped)
func (s *releaseService) ListCandidates(projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error) {
	return s.releaseRepository.GetCandidateItemsForRelease(projectID, releaseID)
}
