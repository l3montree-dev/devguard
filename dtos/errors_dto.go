package dtos

type ExternalReferenceError struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}
