package models

type Advisory struct {
	Model
	AdvisoryName string `json:"name" gorm:"type:text;column:advisory_name"`
}

func (m Advisory) TableName() string {
	return "advisories"
}
