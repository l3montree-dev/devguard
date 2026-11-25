package dtos

type LabelRequest struct {
	Label           string `json:"label" validate:"required,max=256"`
	Description     string `json:"description" validate:"max=2000"`
	BackgroundColor string `json:"background_color" validate:"required,hexcolor"`
}

type AttachLabelRequest struct {
	Labels []string `json:"label" validate:"required,min=1,max=256,dive,max=256"`
}
