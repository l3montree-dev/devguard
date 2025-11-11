package assetversion

type assetMetrics struct {
	EnabledContainerScanning       bool    `json:"enabledContainerScanning"`
	EnabledImageSigning            bool    `json:"enabledImageSigning"`
	VerifiedSupplyChainsPercentage float64 `json:"verifiedSupplyChainsPercentage"`
	EnabledSCA                     bool    `json:"enabledSCA"`
}

type InformationSourceDTO struct {
	Purl string `json:"purl,omitempty"`
	// type can be "csaf", "vex", "sbom"
	Type string `json:"type,omitempty"`
}
