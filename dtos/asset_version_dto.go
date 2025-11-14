package dtos

type AssetMetrics struct {
	EnabledContainerScanning       bool    `json:"enabledContainerScanning"`
	EnabledImageSigning            bool    `json:"enabledImageSigning"`
	VerifiedSupplyChainsPercentage float64 `json:"verifiedSupplyChainsPercentage"`
	EnabledSCA                     bool    `json:"enabledSCA"`
}

type InformationSourceDTO struct {
	URL  string `json:"url,omitempty"`
	Purl string `json:"purl,omitempty"`
	// type can be "csaf", "vex", "sbom"
	Type string `json:"type,omitempty"`
}

type AssetVersionDTO struct {
	CreatedAt      string         `json:"createdAt"`
	UpdatedAt      string         `json:"updatedAt"`
	Name           string         `json:"name"`
	AssetID        string         `json:"assetId"`
	DefaultBranch  bool           `json:"defaultBranch"`
	Slug           string         `json:"slug"`
	Type           string         `json:"type"`
	SigningPubKey  *string        `json:"signingPubKey,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	LastAccessedAt string         `json:"lastAccessedAt,omitempty"`
}
