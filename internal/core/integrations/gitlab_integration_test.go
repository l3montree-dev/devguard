package integrations_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestCreateProjectHook(t *testing.T) {
	t.Run("URL should be set to main devguard", func(t *testing.T) {
		core.LoadConfig()
		core.InitLogger()

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := integrations.CreateProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.main.devguard.org", *results.URL)

	})
	t.Run("URL should be set to stage devguard", func(t *testing.T) {
		core.LoadConfig()
		core.InitLogger()

		os.Setenv("INSTANCE_DOMAIN", "https://api.stage.devguard.org")

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := integrations.CreateProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.stage.devguard.org", *results.URL)

	})
}
