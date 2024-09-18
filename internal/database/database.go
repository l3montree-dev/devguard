package database

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DB = *gorm.DB

func NewConnection(host, user, password, dbname, port string) (*gorm.DB, error) {
	// https://github.com/go-gorm/postgres
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&timezone=UTC", user, password, host, port, dbname),
	}), &gorm.Config{
		Logger: logger.Default,
	})

	if err != nil {
		return nil, err
	}

	return db, nil
}

type PageInfo struct {
	Total    int64 `json:"total"`
	PageSize int   `json:"pageSize"`
	Page     int   `json:"page"`
}
