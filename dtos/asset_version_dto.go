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
}
