package models

type FlawEventType string

const (
	EventTypeDetected FlawEventType = "detected"
	EventTypeFixed    FlawEventType = "fixed"

	//EventTypeRiskAssessmentUpdated FlawEventType = "riskAssessmentUpdated"
	EventTypeAccepted            FlawEventType = "accepted"
	EventTypeMarkedForMitigation FlawEventType = "markedForMitigation"
	EventTypeFalsePositive       FlawEventType = "falsePositive"
	EventTypeMarkedForTransfer   FlawEventType = "markedForTransfer"
)

type FlawEvent struct {
	Model
	Type   FlawEventType `json:"type" gorm:"type:text"`
	FlawID string        `json:"flawId"`
	UserID string        `json:"userId"`

	Justification *string `json:"justification" gorm:"type:text;"`
}

func (m FlawEvent) TableName() string {
	return "flaw_events"
}

func (e FlawEvent) Apply(flaw Flaw) Flaw {
	switch e.Type {
	case EventTypeFixed:
		flaw.State = FlawStateFixed
	case EventTypeDetected:
		flaw.State = FlawStateOpen
	case EventTypeAccepted:
		flaw.State = FlawStateAccepted
	case EventTypeMarkedForMitigation:
		flaw.State = FlawStateMarkedForMitigation
	case EventTypeFalsePositive:
		flaw.State = FlawStateFalsePositive
	case EventTypeMarkedForTransfer:
		flaw.State = FlawStateMarkedForTransfer
	}

	return flaw
}

func NewFixedEvent(flawID string, userID string) FlawEvent {
	return FlawEvent{
		Type:   EventTypeFixed,
		FlawID: flawID,
		UserID: userID,
	}
}

func NewDetectedEvent(flawID string, userID string) FlawEvent {
	return FlawEvent{
		Type:   EventTypeDetected,
		FlawID: flawID,
		UserID: userID,
	}
}

func NewAcceptedEvent(flawID string, userID string, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeFixed,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewMarkedForMitigationEvent(flawID string, userID string, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeMarkedForMitigation,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewFalsePositiveEvent(flawID string, userID string, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeFalsePositive,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}

func NewMarkedForTransferEvent(flawID string, userID string, justification string) FlawEvent {
	return FlawEvent{
		Type:          EventTypeMarkedForTransfer,
		FlawID:        flawID,
		UserID:        userID,
		Justification: &justification,
	}
}
