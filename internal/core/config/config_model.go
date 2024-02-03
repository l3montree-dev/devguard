package config

type Config struct {
	Key string `gorm:"primarykey"`
	Val string `gorm:"type:text"`
}

func (Config) TableName() string {
	return "config"
}
