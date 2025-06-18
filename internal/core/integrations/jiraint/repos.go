package jiraint

//based on https://pkg.go.dev/github.com/andygrunwald/go-jira

type Project struct {
	Expand          string             `json:"expand,omitempty" structs:"expand,omitempty"`
	Self            string             `json:"self,omitempty" structs:"self,omitempty"`
	ID              string             `json:"id,omitempty" structs:"id,omitempty"`
	Key             string             `json:"key,omitempty" structs:"key,omitempty"`
	Description     string             `json:"description,omitempty" structs:"description,omitempty"`
	Lead            User               `json:"lead,omitempty" structs:"lead,omitempty"`
	Components      []ProjectComponent `json:"components,omitempty" structs:"components,omitempty"`
	IssueTypes      []IssueType        `json:"issueTypes,omitempty" structs:"issueTypes,omitempty"`
	URL             string             `json:"url,omitempty" structs:"url,omitempty"`
	Email           string             `json:"email,omitempty" structs:"email,omitempty"`
	AssigneeType    string             `json:"assigneeType,omitempty" structs:"assigneeType,omitempty"`
	Versions        []Version          `json:"versions,omitempty" structs:"versions,omitempty"`
	Name            string             `json:"name,omitempty" structs:"name,omitempty"`
	Roles           map[string]string  `json:"roles,omitempty" structs:"roles,omitempty"`
	AvatarUrls      AvatarUrls         `json:"avatarUrls,omitempty" structs:"avatarUrls,omitempty"`
	ProjectCategory ProjectCategory    `json:"projectCategory,omitempty" structs:"projectCategory,omitempty"`
}

type ProjectComponent struct {
	Self                string `json:"self" structs:"self,omitempty"`
	ID                  string `json:"id" structs:"id,omitempty"`
	Name                string `json:"name" structs:"name,omitempty"`
	Description         string `json:"description" structs:"description,omitempty"`
	Lead                User   `json:"lead,omitempty" structs:"lead,omitempty"`
	AssigneeType        string `json:"assigneeType" structs:"assigneeType,omitempty"`
	Assignee            User   `json:"assignee" structs:"assignee,omitempty"`
	RealAssigneeType    string `json:"realAssigneeType" structs:"realAssigneeType,omitempty"`
	RealAssignee        User   `json:"realAssignee" structs:"realAssignee,omitempty"`
	IsAssigneeTypeValid bool   `json:"isAssigneeTypeValid" structs:"isAssigneeTypeValid,omitempty"`
	Project             string `json:"project" structs:"project,omitempty"`
	ProjectID           int    `json:"projectId" structs:"projectId,omitempty"`
}

type User struct {
	Self            string     `json:"self,omitempty" structs:"self,omitempty"`
	AccountID       string     `json:"accountId,omitempty" structs:"accountId,omitempty"`
	AccountType     string     `json:"accountType,omitempty" structs:"accountType,omitempty"`
	Name            string     `json:"name,omitempty" structs:"name,omitempty"`
	Key             string     `json:"key,omitempty" structs:"key,omitempty"`
	Password        string     `json:"-"`
	EmailAddress    string     `json:"emailAddress,omitempty" structs:"emailAddress,omitempty"`
	AvatarUrls      AvatarUrls `json:"avatarUrls,omitempty" structs:"avatarUrls,omitempty"`
	DisplayName     string     `json:"displayName,omitempty" structs:"displayName,omitempty"`
	Active          bool       `json:"active,omitempty" structs:"active,omitempty"`
	TimeZone        string     `json:"timeZone,omitempty" structs:"timeZone,omitempty"`
	Locale          string     `json:"locale,omitempty" structs:"locale,omitempty"`
	ApplicationKeys []string   `json:"applicationKeys,omitempty" structs:"applicationKeys,omitempty"`
}

type AvatarUrls struct {
	Four8X48  string `json:"48x48,omitempty" structs:"48x48,omitempty"`
	Two4X24   string `json:"24x24,omitempty" structs:"24x24,omitempty"`
	One6X16   string `json:"16x16,omitempty" structs:"16x16,omitempty"`
	Three2X32 string `json:"32x32,omitempty" structs:"32x32,omitempty"`
}

type IssueType struct {
	Self        string `json:"self,omitempty" structs:"self,omitempty"`
	ID          string `json:"id,omitempty" structs:"id,omitempty"`
	Description string `json:"description,omitempty" structs:"description,omitempty"`
	IconURL     string `json:"iconUrl,omitempty" structs:"iconUrl,omitempty"`
	Name        string `json:"name,omitempty" structs:"name,omitempty"`
	Subtask     bool   `json:"subtask,omitempty" structs:"subtask,omitempty"`
	AvatarID    int    `json:"avatarId,omitempty" structs:"avatarId,omitempty"`
}

type Version struct {
	Self            string `json:"self,omitempty" structs:"self,omitempty"`
	ID              string `json:"id,omitempty" structs:"id,omitempty"`
	Name            string `json:"name,omitempty" structs:"name,omitempty"`
	Description     string `json:"description,omitempty" structs:"description,omitempty"`
	Archived        *bool  `json:"archived,omitempty" structs:"archived,omitempty"`
	Released        *bool  `json:"released,omitempty" structs:"released,omitempty"`
	ReleaseDate     string `json:"releaseDate,omitempty" structs:"releaseDate,omitempty"`
	UserReleaseDate string `json:"userReleaseDate,omitempty" structs:"userReleaseDate,omitempty"`
	ProjectID       int    `json:"projectId,omitempty" structs:"projectId,omitempty"` // Unlike other IDs, this is returned as a number
	StartDate       string `json:"startDate,omitempty" structs:"startDate,omitempty"`
}

type ProjectCategory struct {
	Self        string `json:"self" structs:"self,omitempty"`
	ID          string `json:"id" structs:"id,omitempty"`
	Name        string `json:"name" structs:"name,omitempty"`
	Description string `json:"description" structs:"description,omitempty"`
}
