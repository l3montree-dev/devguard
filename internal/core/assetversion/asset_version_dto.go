package assetversion

type assetMetrics struct {
	EnabledContainerScanning       bool    `json:"enabledContainerScanning"`
	EnabledImageSigning            bool    `json:"enabledImageSigning"`
	VerifiedSupplyChainsPercentage float64 `json:"verifiedSupplyChainsPercentage"`
	EnabledSCA                     bool    `json:"enabledSCA"`
}
