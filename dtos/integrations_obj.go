package dtos

type GitlabIntegration struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
}

type JiraIntegration struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`
	UserEmail       string `json:"userEmail"`
}

type RedmineIntegration struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	URL             string `json:"url"`
	ObfuscatedToken string `json:"obfuscatedToken"`

	TrackerID       int  `json:"trackerId"`
	DefaultStatusID *int `json:"defaultStatusId"`
	CloseStatusID   *int `json:"closeStatusId"`

	LowPriorityID      *int `json:"lowPriorityId"`
	MediumPriorityID   *int `json:"mediumPriorityId"`
	HighPriorityID     *int `json:"highPriorityId"`
	CriticalPriorityID *int `json:"criticalPriorityId"`

	MermaidIntegration string `json:"mermaidIntegration"`
}

type RedmineIntegrationProperties struct {
	Trackers   []RedmineTracker  `json:"trackers"`
	Statuses   []RedmineStatus   `json:"statuses"`
	Priorities []RedminePriority `json:"priorities"`
}

type RedmineTracker struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type RedmineStatus struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type RedminePriority struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type WebhookIntegration struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	SbomEnabled bool   `json:"sbomEnabled"`
	VulnEnabled bool   `json:"vulnEnabled"`
}
