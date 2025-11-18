package dtos

import (
	"time"

	"github.com/google/uuid"
)

type ComponentType string

const (
	ComponentTypeApplication          ComponentType = "application"
	ComponentTypeContainer            ComponentType = "container"
	ComponentTypeData                 ComponentType = "data"
	ComponentTypeDevice               ComponentType = "device"
	ComponentTypeDeviceDriver         ComponentType = "device-driver"
	ComponentTypeFile                 ComponentType = "file"
	ComponentTypeFirmware             ComponentType = "firmware"
	ComponentTypeFramework            ComponentType = "framework"
	ComponentTypeLibrary              ComponentType = "library"
	ComponentTypeMachineLearningModel ComponentType = "machine-learning-model"
	ComponentTypeOS                   ComponentType = "operating-system"
	ComponentTypePlatform             ComponentType = "platform"
)

type ComponentProjectDTO struct {
	// project name like "github.com/facebook/react"
	ProjectKey      string `json:"projectKey" gorm:"primaryKey;column:project_key"`
	StarsCount      int    `json:"starsCount" gorm:"column:stars_count"`
	ForksCount      int    `json:"forksCount" gorm:"column:forks_count"`
	OpenIssuesCount int    `json:"openIssuesCount" gorm:"column:open_issues_count"`
	Homepage        string `json:"homepage"`
	License         string `json:"license"`
	Description     string `json:"description"`

	ScoreCard      map[string]any
	ScoreCardScore *float64  `json:"scoreCardScore" gorm:"column:score_card_score"`
	UpdatedAt      time.Time `json:"updatedAt" gorm:"column:updated_at"`
}

type ComponentDTO struct {
	Purl          string                   `json:"purl" gorm:"primaryKey;column:purl"` // without qualifiers!
	Dependencies  []ComponentDependencyDTO `json:"dependsOn" gorm:"hasMany;"`
	ComponentType ComponentType            `json:"componentType"`
	Version       string                   `json:"version"`
	License       *string                  `json:"license"`
	Published     *time.Time               `json:"published"`

	ComponentProject     *ComponentProjectDTO `json:"project" gorm:"foreignKey:ComponentProjectKey;references:ProjectKey;constraint:OnDelete:CASCADE;"`
	ComponentProjectKey  *string              `json:"projectId" gorm:"column:project_key"`
	IsLicenseOverwritten bool                 `json:"isLicenseOverwritten" gorm:"-"`
}

type ComponentDependencyDTO struct {
	ID            uuid.UUID `json:"id"`
	ComponentPurl string    `json:"componentPurl"`
	// the provided sbom from cyclondx only contains the transitive dependencies, which do really get used
	// this means, that the dependency graph between people using the same library might differ, since they use it differently
	// we use edges, which provide the information, that a component is used by another component in one asset
	DependencyPurl string        `json:"dependencyPurl"` // will be nil, for direct dependencies
	Artifacts      []ArtifactDTO `json:"artifacts"`
	Component      ComponentDTO  `json:"component"`
	Dependency     ComponentDTO  `json:"dependency"`
}
