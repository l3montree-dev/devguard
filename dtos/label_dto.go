package dtos

type LabelRequest struct {
	Label           string `json:"label" validate:"required,max=256"`
	BackgroundColor string `json:"background_color" validate:"required,hexcolor"`
}

type AttachLabelRequest struct {
	Labels []string `json:"label" validate:"required"`
}
