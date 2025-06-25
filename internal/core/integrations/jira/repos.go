package jira

import (
	"time"
)

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

type Issue struct {
	Expand         string               `json:"expand,omitempty" structs:"expand,omitempty"`
	ID             string               `json:"id,omitempty" structs:"id,omitempty"`
	Self           string               `json:"self,omitempty" structs:"self,omitempty"`
	Key            string               `json:"key,omitempty" structs:"key,omitempty"`
	Fields         *IssueFields         `json:"fields,omitempty" structs:"fields,omitempty"`
	RenderedFields *IssueRenderedFields `json:"renderedFields,omitempty" structs:"renderedFields,omitempty"`
	Changelog      *Changelog           `json:"changelog,omitempty" structs:"changelog,omitempty"`
	Transitions    []Transition         `json:"transitions,omitempty" structs:"transitions,omitempty"`
	Names          map[string]string    `json:"names,omitempty" structs:"names,omitempty"`
}
type Changelog struct {
	Histories []ChangelogHistory `json:"histories,omitempty"`
}

type Transition struct {
	ID     string                     `json:"id" structs:"id"`
	Name   string                     `json:"name" structs:"name"`
	To     Status                     `json:"to" structs:"status"`
	Fields map[string]TransitionField `json:"fields" structs:"fields"`
}

// TransitionField represents the value of one Transition
type TransitionField struct {
	Required bool `json:"required" structs:"required"`
}
type ChangelogHistory struct {
	Id      string           `json:"id" structs:"id"`
	Author  User             `json:"author" structs:"author"`
	Created string           `json:"created" structs:"created"`
	Items   []ChangelogItems `json:"items" structs:"items"`
}
type ChangelogItems struct {
	Field      string      `json:"field" structs:"field"`
	FieldType  string      `json:"fieldtype" structs:"fieldtype"`
	From       interface{} `json:"from" structs:"from"`
	FromString string      `json:"fromString" structs:"fromString"`
	To         interface{} `json:"to" structs:"to"`
	ToString   string      `json:"toString" structs:"toString"`
}
type IssueRenderedFields struct {
	// TODO Missing fields
	//      * "aggregatetimespent": null,
	//      * "workratio": -1,
	//      * "lastViewed": null,
	//      * "aggregatetimeoriginalestimate": null,
	//      * "aggregatetimeestimate": null,
	//      * "environment": null,
	Resolutiondate string    `json:"resolutiondate,omitempty" structs:"resolutiondate,omitempty"`
	Created        string    `json:"created,omitempty" structs:"created,omitempty"`
	Duedate        string    `json:"duedate,omitempty" structs:"duedate,omitempty"`
	Updated        string    `json:"updated,omitempty" structs:"updated,omitempty"`
	Comments       *Comments `json:"comment,omitempty" structs:"comment,omitempty"`
	Description    string    `json:"description,omitempty" structs:"description,omitempty"`
}

// Resolution represents a resolution of a Jira issue.
// Typical types are "Fixed", "Suspended", "Won't Fix", ...
type Resolution struct {
	Self        string `json:"self" structs:"self"`
	ID          string `json:"id" structs:"id"`
	Description string `json:"description" structs:"description"`
	Name        string `json:"name" structs:"name"`
}

// Priority represents a priority of a Jira issue.
// Typical types are "Normal", "Moderate", "Urgent", ...
type Priority struct {
	Self        string `json:"self,omitempty" structs:"self,omitempty"`
	IconURL     string `json:"iconUrl,omitempty" structs:"iconUrl,omitempty"`
	Name        string `json:"name,omitempty" structs:"name,omitempty"`
	ID          string `json:"id,omitempty" structs:"id,omitempty"`
	StatusColor string `json:"statusColor,omitempty" structs:"statusColor,omitempty"`
	Description string `json:"description,omitempty" structs:"description,omitempty"`
}

// Progress represents the progress of a Jira issue.
type Progress struct {
	Progress int `json:"progress" structs:"progress"`
	Total    int `json:"total" structs:"total"`
	Percent  int `json:"percent" structs:"percent"`
}

// Watches represents a type of how many and which user are "observing" a Jira issue to track the status / updates.
type Watches struct {
	Self       string     `json:"self,omitempty" structs:"self,omitempty"`
	WatchCount int        `json:"watchCount,omitempty" structs:"watchCount,omitempty"`
	IsWatching bool       `json:"isWatching,omitempty" structs:"isWatching,omitempty"`
	Watchers   []*Watcher `json:"watchers,omitempty" structs:"watchers,omitempty"`
}

// Watcher represents a simplified user that "observes" the issue
type Watcher struct {
	Self        string `json:"self,omitempty" structs:"self,omitempty"`
	Name        string `json:"name,omitempty" structs:"name,omitempty"`
	AccountID   string `json:"accountId,omitempty" structs:"accountId,omitempty"`
	DisplayName string `json:"displayName,omitempty" structs:"displayName,omitempty"`
	Active      bool   `json:"active,omitempty" structs:"active,omitempty"`
}

// TimeTracking represents the timetracking fields of a Jira issue.
type TimeTracking struct {
	OriginalEstimate         string `json:"originalEstimate,omitempty" structs:"originalEstimate,omitempty"`
	RemainingEstimate        string `json:"remainingEstimate,omitempty" structs:"remainingEstimate,omitempty"`
	TimeSpent                string `json:"timeSpent,omitempty" structs:"timeSpent,omitempty"`
	OriginalEstimateSeconds  int    `json:"originalEstimateSeconds,omitempty" structs:"originalEstimateSeconds,omitempty"`
	RemainingEstimateSeconds int    `json:"remainingEstimateSeconds,omitempty" structs:"remainingEstimateSeconds,omitempty"`
	TimeSpentSeconds         int    `json:"timeSpentSeconds,omitempty" structs:"timeSpentSeconds,omitempty"`
}

// Component represents a "component" of a Jira issue.
// Components can be user defined in every Jira instance.
type Component struct {
	Self        string `json:"self,omitempty" structs:"self,omitempty"`
	ID          string `json:"id,omitempty" structs:"id,omitempty"`
	Name        string `json:"name,omitempty" structs:"name,omitempty"`
	Description string `json:"description,omitempty" structs:"description,omitempty"`
}
type IssueFields struct {
	// TODO Missing fields
	//      * "workratio": -1,
	//      * "lastViewed": null,
	//      * "environment": null,
	Expand      string      `json:"expand,omitempty" structs:"expand,omitempty"`
	Type        IssueType   `json:"issuetype,omitempty" structs:"issuetype,omitempty"`
	Project     Project     `json:"project,omitempty" structs:"project,omitempty"`
	Environment string      `json:"environment,omitempty" structs:"environment,omitempty"`
	Resolution  *Resolution `json:"resolution,omitempty" structs:"resolution,omitempty"`
	Priority    *Priority   `json:"priority,omitempty" structs:"priority,omitempty"`
	//Resolutiondate                Time              `json:"resolutiondate,omitempty" structs:"resolutiondate,omitempty"`
	//Created                       Time              `json:"created,omitempty" structs:"created,omitempty"`
	//Duedate                       Date              `json:"duedate,omitempty" structs:"duedate,omitempty"`
	Watches  *Watches `json:"watches,omitempty" structs:"watches,omitempty"`
	Assignee *User    `json:"assignee,omitempty" structs:"assignee,omitempty"`
	//Updated                       Time              `json:"updated,omitempty" structs:"updated,omitempty"`
	Description ADF          `json:"description,omitempty" structs:"description,omitempty"`
	Summary     string       `json:"summary,omitempty" structs:"summary,omitempty"`
	Creator     *User        `json:"creator,omitempty" structs:"creator,omitempty"`
	Reporter    *User        `json:"reporter,omitempty" structs:"reporter,omitempty"`
	Components  []*Component `json:"components,omitempty" structs:"components,omitempty"`
	Status      *Status      `json:"status,omitempty" structs:"status,omitempty"`
	//StatusCategoryChangeDate      Time              `json:"statuscategorychangedate,omitempty" structs:"statuscategorychangedate,omitempty"`
	Progress                      *Progress         `json:"progress,omitempty" structs:"progress,omitempty"`
	AggregateProgress             *Progress         `json:"aggregateprogress,omitempty" structs:"aggregateprogress,omitempty"`
	TimeTracking                  *TimeTracking     `json:"timetracking,omitempty" structs:"timetracking,omitempty"`
	TimeSpent                     int               `json:"timespent,omitempty" structs:"timespent,omitempty"`
	TimeEstimate                  int               `json:"timeestimate,omitempty" structs:"timeestimate,omitempty"`
	TimeOriginalEstimate          int               `json:"timeoriginalestimate,omitempty" structs:"timeoriginalestimate,omitempty"`
	Worklog                       *Worklog          `json:"worklog,omitempty" structs:"worklog,omitempty"`
	IssueLinks                    []*IssueLink      `json:"issuelinks,omitempty" structs:"issuelinks,omitempty"`
	Comments                      *Comments         `json:"comment,omitempty" structs:"comment,omitempty"`
	FixVersions                   []*FixVersion     `json:"fixVersions,omitempty" structs:"fixVersions,omitempty"`
	AffectsVersions               []*AffectsVersion `json:"versions,omitempty" structs:"versions,omitempty"`
	Labels                        []string          `json:"labels,omitempty" structs:"labels,omitempty"`
	Subtasks                      []*Subtasks       `json:"subtasks,omitempty" structs:"subtasks,omitempty"`
	Attachments                   []*Attachment     `json:"attachment,omitempty" structs:"attachment,omitempty"`
	Epic                          *Epic             `json:"epic,omitempty" structs:"epic,omitempty"`
	Sprint                        *Sprint           `json:"sprint,omitempty" structs:"sprint,omitempty"`
	Parent                        *Parent           `json:"parent,omitempty" structs:"parent,omitempty"`
	AggregateTimeOriginalEstimate int               `json:"aggregatetimeoriginalestimate,omitempty" structs:"aggregatetimeoriginalestimate,omitempty"`
	AggregateTimeSpent            int               `json:"aggregatetimespent,omitempty" structs:"aggregatetimespent,omitempty"`
	AggregateTimeEstimate         int               `json:"aggregatetimeestimate,omitempty" structs:"aggregatetimeestimate,omitempty"`
	// Unknowns                      tcontainer.MarshalMap
}

// Subtasks represents all issues of a parent issue.
type Subtasks struct {
	ID     string      `json:"id" structs:"id"`
	Key    string      `json:"key" structs:"key"`
	Self   string      `json:"self" structs:"self"`
	Fields IssueFields `json:"fields" structs:"fields"`
}

// Worklog represents the work log of a Jira issue.
// One Worklog contains zero or n WorklogRecords
// Jira Wiki: https://confluence.atlassian.com/jira/logging-work-on-an-issue-185729605.html
type Worklog struct {
	StartAt    int             `json:"startAt" structs:"startAt"`
	MaxResults int             `json:"maxResults" structs:"maxResults"`
	Total      int             `json:"total" structs:"total"`
	Worklogs   []WorklogRecord `json:"worklogs" structs:"worklogs"`
}

// WorklogRecord represents one entry of a Worklog
type WorklogRecord struct {
	Self             string           `json:"self,omitempty" structs:"self,omitempty"`
	Author           *User            `json:"author,omitempty" structs:"author,omitempty"`
	UpdateAuthor     *User            `json:"updateAuthor,omitempty" structs:"updateAuthor,omitempty"`
	Comment          string           `json:"comment,omitempty" structs:"comment,omitempty"`
	Created          *Time            `json:"created,omitempty" structs:"created,omitempty"`
	Updated          *Time            `json:"updated,omitempty" structs:"updated,omitempty"`
	Started          *Time            `json:"started,omitempty" structs:"started,omitempty"`
	TimeSpent        string           `json:"timeSpent,omitempty" structs:"timeSpent,omitempty"`
	TimeSpentSeconds int              `json:"timeSpentSeconds,omitempty" structs:"timeSpentSeconds,omitempty"`
	ID               string           `json:"id,omitempty" structs:"id,omitempty"`
	IssueID          string           `json:"issueId,omitempty" structs:"issueId,omitempty"`
	Properties       []EntityProperty `json:"properties,omitempty"`
}

// FixVersion represents a software release in which an issue is fixed.
type FixVersion struct {
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

// AffectsVersion represents a software release which is affected by an issue.
type AffectsVersion Version

type Time time.Time

// Date represents the Date definition of Jira as a time.Time of go
type Date time.Time
type Parent struct {
	ID  string `json:"id,omitempty" structs:"id,omitempty"`
	Key string `json:"key,omitempty" structs:"key,omitempty"`
}

type Sprint struct {
	ID            int        `json:"id" structs:"id"`
	Name          string     `json:"name" structs:"name"`
	CompleteDate  *time.Time `json:"completeDate" structs:"completeDate"`
	EndDate       *time.Time `json:"endDate" structs:"endDate"`
	StartDate     *time.Time `json:"startDate" structs:"startDate"`
	OriginBoardID int        `json:"originBoardId" structs:"originBoardId"`
	Self          string     `json:"self" structs:"self"`
	State         string     `json:"state" structs:"state"`
}

// Epic represents the epic to which an issue is associated
// Not that this struct does not process the returned "color" value
type Epic struct {
	ID      int    `json:"id" structs:"id"`
	Key     string `json:"key" structs:"key"`
	Self    string `json:"self" structs:"self"`
	Name    string `json:"name" structs:"name"`
	Summary string `json:"summary" structs:"summary"`
	Done    bool   `json:"done" structs:"done"`
}

// Attachment represents a Jira attachment
type Attachment struct {
	Self      string `json:"self,omitempty" structs:"self,omitempty"`
	ID        string `json:"id,omitempty" structs:"id,omitempty"`
	Filename  string `json:"filename,omitempty" structs:"filename,omitempty"`
	Author    *User  `json:"author,omitempty" structs:"author,omitempty"`
	Created   string `json:"created,omitempty" structs:"created,omitempty"`
	Size      int    `json:"size,omitempty" structs:"size,omitempty"`
	MimeType  string `json:"mimeType,omitempty" structs:"mimeType,omitempty"`
	Content   string `json:"content,omitempty" structs:"content,omitempty"`
	Thumbnail string `json:"thumbnail,omitempty" structs:"thumbnail,omitempty"`
}

// IssueLink represents a link between two issues in Jira.
type IssueLink struct {
	ID           string        `json:"id,omitempty" structs:"id,omitempty"`
	Self         string        `json:"self,omitempty" structs:"self,omitempty"`
	Type         IssueLinkType `json:"type" structs:"type"`
	OutwardIssue *Issue        `json:"outwardIssue" structs:"outwardIssue"`
	InwardIssue  *Issue        `json:"inwardIssue" structs:"inwardIssue"`
	Comment      *Comment      `json:"comment,omitempty" structs:"comment,omitempty"`
}

type Status struct {
	Self           string         `json:"self" structs:"self"`
	Description    string         `json:"description" structs:"description"`
	IconURL        string         `json:"iconUrl" structs:"iconUrl"`
	Name           string         `json:"name" structs:"name"`
	ID             string         `json:"id" structs:"id"`
	StatusCategory StatusCategory `json:"statusCategory" structs:"statusCategory"`
}

type StatusCategory struct {
	Self      string `json:"self" structs:"self"`
	ID        int    `json:"id" structs:"id"`
	Name      string `json:"name" structs:"name"`
	Key       string `json:"key" structs:"key"`
	ColorName string `json:"colorName" structs:"colorName"`
}

// IssueLinkType represents a type of a link between to issues in Jira.
// Typical issue link types are "Related to", "Duplicate", "Is blocked by", etc.
type IssueLinkType struct {
	ID      string `json:"id,omitempty" structs:"id,omitempty"`
	Self    string `json:"self,omitempty" structs:"self,omitempty"`
	Name    string `json:"name" structs:"name"`
	Inward  string `json:"inward" structs:"inward"`
	Outward string `json:"outward" structs:"outward"`
}

// Comments represents a list of Comment.
type Comments struct {
	Comments []*Comment `json:"comments,omitempty" structs:"comments,omitempty"`
}

// Comment represents a comment by a person to an issue in Jira.
type Comment struct {
	ID           string             `json:"id,omitempty" structs:"id,omitempty"`
	Self         string             `json:"self,omitempty" structs:"self,omitempty"`
	Name         string             `json:"name,omitempty" structs:"name,omitempty"`
	Author       *User              `json:"author,omitempty" structs:"author,omitempty"`
	Body         string             `json:"body,omitempty" structs:"body,omitempty"`
	UpdateAuthor *User              `json:"updateAuthor,omitempty" structs:"updateAuthor,omitempty"`
	Updated      string             `json:"updated,omitempty" structs:"updated,omitempty"`
	Created      string             `json:"created,omitempty" structs:"created,omitempty"`
	Visibility   *CommentVisibility `json:"visibility,omitempty" structs:"visibility,omitempty"`

	// A list of comment properties. Optional on create and update.
	Properties []EntityProperty `json:"properties,omitempty" structs:"properties,omitempty"`
}

// CommentVisibility represents he visibility of a comment.
// E.g. Type could be "role" and Value "Administrators"
type CommentVisibility struct {
	Type  string `json:"type,omitempty" structs:"type,omitempty"`
	Value string `json:"value,omitempty" structs:"value,omitempty"`
}

type EntityProperty struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

//

type ADF struct {
	Version int          `json:"version"`
	Type    string       `json:"type"`
	Content []ADFContent `json:"content"`
}

type ADFContent struct {
	Type    string             `json:"type"`
	Text    string             `json:"text,omitempty"`
	Marks   []ADFMark          `json:"marks,omitempty"`
	Content []ADFContent       `json:"content,omitempty"`
	Attrs   *ADFMarkAttributes `json:"attrs,omitempty"`
}

type ADFMark struct {
	Type  string             `json:"type"`
	Attrs *ADFMarkAttributes `json:"attrs,omitempty"`
}

type ADFMarkAttributes struct {
	Level    int    `json:"level,omitempty"`
	Href     string `json:"href,omitempty"`
	Language string `json:"language,omitempty"`
}
