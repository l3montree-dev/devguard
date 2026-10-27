package redmineint

import (
	"time"
)

type Time time.Time

type Id struct {
	ID int `json:"id" structs:"id"`
}

type NamedId struct {
	ID   int    `json:"id" structs:"id"`
	Name string `json:"name" structs:"name"`
}

type ProjectsResponse struct {
	Projects   []*Project `json:"projects" structs:"projects"`
	TotalCount int        `json:"total_count" structs:"total_count"`
	Offset     int        `json:"offset" structs:"offset"`
	Limit      int        `json:"limit" structs:"limit"`
}

type Project struct {
	ID          int    `json:"id" structs:"id"`
	Name        string `json:"name" structs:"name"`
	Identifier  string `json:"identifier" structs:"identifier"`
	Description string `json:"description,omitempty" structs:"description,omitempty"`
}

type IssueStatus struct {
	ID       int    `json:"id" structs:"id"`
	Name     string `json:"name" structs:"name"`
	IsClosed bool   `json:"is_closed" structs:"is_closed"`
}

type CustomField struct {
	ID    int    `json:"id" structs:"id"`
	Name  string `json:"name" structs:"name"`
	Value any    `json:"value,omitempty" structs:"value,omitempty"`
}

type IssueResponse struct {
	Issue Issue `json:"issue" structs:"issue"`
}

type Issue struct {
	ID           int           `json:"id" structs:"id"`
	Project      NamedId       `json:"project" structs:"project"`
	Tracker      NamedId       `json:"tracker" structs:"tracker"`
	Status       IssueStatus   `json:"status" structs:"status"`
	Priority     NamedId       `json:"priority" structs:"priority"`
	Author       NamedId       `json:"author" structs:"author"`
	FixedVersion NamedId       `json:"fixed_version,omitempty" structs:"fixed_version,omitempty"`
	Parent       Id            `json:"parent,omitempty" structs:"parent,omitempty"`
	Subject      string        `json:"subject" structs:"subject"`
	Description  string        `json:"description,omitempty" structs:"description,omitempty"`
	CustomFields []CustomField `json:"custom_fields,omitempty" structs:"custom_fields,omitempty"`
}

type IssueCreateOptions struct {
	ProjectID   int     `json:"project_id" structs:"project_id"`
	Subject     *string `json:"subject" structs:"subject"`
	Description *string `json:"description,omitempty" structs:"description,omitempty"`
	StatusID    *int    `json:"status_id,omitempty" structs:"status_id,omitempty"`
	PriorityID  *int    `json:"priority_id,omitempty" structs:"priority_id,omitempty"`
	TrackerID   int     `json:"tracker_id,omitempty" structs:"tracker_id,omitempty"`
}

type IssueCreateRequest struct {
	Issue *IssueCreateOptions `json:"issue" structs:"issue"`
}

type IssueEditOptions struct {
	Subject     *string `json:"subject,omitempty" structs:"subject,omitempty"`
	Description *string `json:"description,omitempty" structs:"description,omitempty"`
	StatusID    *int    `json:"status_id,omitempty" structs:"status_id,omitempty"`
	PriorityID  *int    `json:"priority_id,omitempty" structs:"priority_id,omitempty"`
	Notes       string  `json:"notes,omitempty" structs:"notes,omitempty"`
}

type IssueUpdateRequest struct {
	Issue *IssueEditOptions `json:"issue" structs:"issue"`
}

type Tracker struct {
	ID            int     `json:"id" structs:"id"`
	Name          string  `json:"name" structs:"name"`
	DefaultStatus NamedId `json:"default_status" structs:"default_status"`
}

type TrackersResponse struct {
	Trackers []*Tracker `json:"trackers" structs:"trackers"`
}

type Status struct {
	ID       int    `json:"id" structs:"id"`
	Name     string `json:"name" structs:"name"`
	IsClosed bool   `json:"is_closed" structs:"is_closed"`
}

type StatusesResponse struct {
	Statuses []*Status `json:"issue_statuses" structs:"issue_statuses"`
}

type Priority struct {
	ID        int    `json:"id" structs:"id"`
	Name      string `json:"name" structs:"name"`
	IsDefault bool   `json:"is_default" structs:"is_default"`
	Active    bool   `json:"active" structs:"active"`
}

type PrioritiesResponse struct {
	Priorities []*Priority `json:"issue_priorities" structs:"issue_priorities"`
}
