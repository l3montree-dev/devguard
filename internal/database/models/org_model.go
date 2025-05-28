package models

import "github.com/l3montree-dev/devguard/internal/database"

type Org struct {
	Model
	Name                   string    `json:"name" gorm:"type:text"`
	ContactPhoneNumber     *string   `json:"contactPhoneNumber" gorm:"type:text"`
	NumberOfEmployees      *int      `json:"numberOfEmployees"`
	Country                *string   `json:"country" gorm:"type:text"`
	Industry               *string   `json:"industry" gorm:"type:text"`
	CriticalInfrastructure bool      `json:"criticalInfrastructure"`
	ISO27001               bool      `json:"iso27001"`
	NIST                   bool      `json:"nist"`
	Grundschutz            bool      `json:"grundschutz"`
	Projects               []Project `json:"projects" gorm:"foreignKey:OrganizationID;"`
	Slug                   string    `json:"slug" gorm:"type:text;unique;not null;index"`
	Description            string    `json:"description" gorm:"type:text"`

	GithubAppInstallations []GithubAppInstallation `json:"githubAppInstallations" gorm:"foreignKey:OrgID;"`

	GitLabIntegrations []GitLabIntegration `json:"gitLabIntegrations" gorm:"foreignKey:OrgID;"`

	IsPublic bool `json:"isPublic" gorm:"default:false;"`

	ConfigFiles database.JSONB `json:"configFiles" gorm:"type:jsonb"`

	Language string `json:"language" gorm:"type:text;size:2"`
}

func (m Model) TableName() string {
	return "organizations"
}
