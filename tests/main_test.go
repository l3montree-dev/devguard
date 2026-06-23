package tests

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("RBAC_CONFIG_PATH", "../config/rbac_model.conf")
	os.Setenv("FRONTEND_URL", "http://localhost:3000")
	os.Exit(m.Run())
}
