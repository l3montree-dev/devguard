package models

type SupplyChain struct {
	SupplyChainID           string `json:"supplyChainId" gorm:"column:supply_chain_id;primaryKey"`
	Verified                bool   `json:"verified" gorm:"column:verified"`
	SupplyChainOutputDigest string `json:"supplyChainOutputDigest" gorm:"column:supply_chain_output_digest"`
}

func (SupplyChain) TableName() string {
	return "supply_chain"
}
