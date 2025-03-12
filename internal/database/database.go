package database

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewConnection(host, user, password, dbname, port string) (*gorm.DB, error) {
	// https://github.com/go-gorm/postgres
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname),
	}), &gorm.Config{
		Logger: logger.Default,
	})

	if err != nil {
		return nil, err
	}

	return db, nil
}

func IsDuplicateKeyError(err error) bool {
	return strings.HasPrefix(err.Error(), "ERROR: duplicate key value violates unique constraint")
}

type PageInfo struct {
	Total    int64 `json:"total"`
	PageSize int   `json:"pageSize"`
	Page     int   `json:"page"`
}

type JSONB map[string]any

// Value Marshal
func (jsonField JSONB) Value() (driver.Value, error) {
	return json.Marshal(jsonField)
}

// Scan Unmarshal
func (jsonField *JSONB) Scan(value any) error {
	data, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(data, &jsonField)
}

func JsonbFromStruct(m any) (JSONB, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var jsonb JSONB
	err = json.Unmarshal(data, &jsonb)
	if err != nil {
		return nil, err
	}
	return jsonb, nil
}
