// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reads a column straight from the table, bypassing the repository so the decrypt path
// never runs; this is how we prove the value is stored encrypted at rest
func rawColumn(t *testing.T, db shared.DB, table, column string, id uuid.UUID) string {
	t.Helper()
	var value string
	err := db.Raw(fmt.Sprintf("SELECT %s FROM %s WHERE id = ?", column, table), id).Scan(&value).Error
	require.NoError(t, err)
	return value
}

func assertEncryptedAtRest(t *testing.T, stored, plaintext string) {
	t.Helper()
	assert.NotEqual(t, plaintext, stored, "value must not be stored as plaintext")
	assert.True(t, strings.HasPrefix(stored, testEncryptionPrefix), "stored value must carry the versioned encryption prefix")
}

// TestRepositoryEncryptionAtRest verifies the integration repositories encrypt sensitive
// fields before save, keep the in-memory model in plaintext afterwards, round trip back to
// the original on read, and still read legacy rows that were written before encryption.
func TestRepositoryEncryptionAtRest(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	enc, err := services.NewDBEncryptionServiceFromKey([]byte(testEncryptionKey))
	require.NoError(t, err)

	org, project, _, _ := CreateOrgProjectAndAssetAssetVersion(db)
	ctx := context.Background()

	t.Run("GitLabIntegration", func(t *testing.T) {
		repo := repositories.NewGitLabIntegrationRepository(db, enc)
		const plaintext = "glpat-gitlab-secret"

		integration := models.GitLabIntegration{Name: "gl", AccessToken: plaintext, OrgID: org.ID}
		require.NoError(t, repo.Save(ctx, nil, &integration))

		assert.Equal(t, plaintext, integration.AccessToken, "Save must restore the plaintext on the in-memory model")
		assertEncryptedAtRest(t, rawColumn(t, db, "gitlab_integrations", "access_token", integration.ID), plaintext)

		read, err := repo.Read(ctx, nil, integration.ID)
		require.NoError(t, err)
		assert.Equal(t, plaintext, read.AccessToken)

		found, err := repo.FindByOrganizationID(ctx, nil, org.ID)
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.Equal(t, plaintext, found[0].AccessToken)

		// a row written before encryption existed has no prefix and must read back untouched
		legacy := models.GitLabIntegration{Name: "legacy", AccessToken: "legacy-plaintext", OrgID: org.ID}
		require.NoError(t, db.Create(&legacy).Error)
		readLegacy, err := repo.Read(ctx, nil, legacy.ID)
		require.NoError(t, err)
		assert.Equal(t, "legacy-plaintext", readLegacy.AccessToken)
	})

	t.Run("GitLabOauth2Token", func(t *testing.T) {
		repo := repositories.NewGitlabOauth2TokenRepository(db, enc)
		const accessPlaintext = "oauth-access-secret"
		const refreshPlaintext = "oauth-refresh-secret"

		token := models.GitLabOauth2Token{
			AccessToken:  accessPlaintext,
			RefreshToken: refreshPlaintext,
			UserID:       "user-1",
			ProviderID:   "gitlab",
		}
		require.NoError(t, repo.Save(ctx, nil, &token))

		assert.Equal(t, accessPlaintext, token.AccessToken, "Save must restore the plaintext access token in memory")
		assert.Equal(t, refreshPlaintext, token.RefreshToken, "Save must restore the plaintext refresh token in memory")

		// both sensitive fields must be encrypted at rest, not just the access token
		assertEncryptedAtRest(t, rawColumn(t, db, "gitlab_oauth2_tokens", "access_token", token.ID), accessPlaintext)
		assertEncryptedAtRest(t, rawColumn(t, db, "gitlab_oauth2_tokens", "refresh_token", token.ID), refreshPlaintext)

		found, err := repo.FindByUserIDAndProviderID(ctx, nil, "user-1", "gitlab")
		require.NoError(t, err)
		assert.Equal(t, accessPlaintext, found.AccessToken)
		assert.Equal(t, refreshPlaintext, found.RefreshToken)
	})

	t.Run("JiraIntegration", func(t *testing.T) {
		repo := repositories.NewJiraIntegrationRepository(db, enc)
		const plaintext = "jira-api-token"

		integration := models.JiraIntegration{Name: "jira", AccessToken: plaintext, URL: "https://jira.example", OrgID: org.ID}
		require.NoError(t, repo.Save(ctx, nil, &integration))

		assert.Equal(t, plaintext, integration.AccessToken, "Save must restore the plaintext on the in-memory model")
		assertEncryptedAtRest(t, rawColumn(t, db, "jira_integrations", "access_token", integration.ID), plaintext)

		read, err := repo.Read(ctx, nil, integration.ID)
		require.NoError(t, err)
		assert.Equal(t, plaintext, read.AccessToken)

		found, err := repo.FindByOrganizationID(ctx, nil, org.ID)
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.Equal(t, plaintext, found[0].AccessToken)
	})

	t.Run("WebhookIntegration", func(t *testing.T) {
		repo := repositories.NewWebhookRepository(db, enc)
		plaintext := "webhook-signing-secret"

		webhook := models.WebhookIntegration{URL: "https://hook.example", Secret: &plaintext, OrgID: org.ID, ProjectID: &project.ID}
		require.NoError(t, repo.Save(ctx, nil, &webhook))

		require.NotNil(t, webhook.Secret)
		assert.Equal(t, plaintext, *webhook.Secret, "Save must restore the plaintext secret in memory")
		assertEncryptedAtRest(t, rawColumn(t, db, "webhook_integrations", "secret", webhook.ID), plaintext)

		read, err := repo.Read(ctx, nil, webhook.ID)
		require.NoError(t, err)
		require.NotNil(t, read.Secret)
		assert.Equal(t, plaintext, *read.Secret)

		// a webhook without a secret must save and read without touching encryption
		noSecret := models.WebhookIntegration{URL: "https://hook2.example", OrgID: org.ID, ProjectID: &project.ID}
		require.NoError(t, repo.Save(ctx, nil, &noSecret))
		readNoSecret, err := repo.Read(ctx, nil, noSecret.ID)
		require.NoError(t, err)
		assert.Nil(t, readNoSecret.Secret)
	})
}
