package dtos

type AdvisoryEventType string

const (
	AdvisoryEventTypeCreated   AdvisoryEventType = "created"
	AdvisoryEventTypeUpdated   AdvisoryEventType = "updated"
	AdvisoryEventTypePublished AdvisoryEventType = "published"
	AdvisoryEventTypeWithdrawn AdvisoryEventType = "withdrawn"
)
