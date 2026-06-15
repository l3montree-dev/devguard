// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CheckForValidTokenByFingerprint is the PAT validity check on the real
// authentication path (session middleware → VerifyRequestSignature →
// getPubKeyAndUserIDUsingFingerprint). These tests pin its expiry enforcement:
// a valid token is returned, an expired one is rejected like a missing token,
// and an unknown fingerprint is rejected too.
func TestPATCheckForValidTokenByFingerprintEnforcesExpiry(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	patService := services.NewPatService(repositories.NewPATRepository(db))
	ctx := context.Background()

	createPAT := func(fingerprint string, expiry time.Time) {
		pat := models.PAT{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			PubKey:      utils.Ptr("deadbeef"),
			Description: "expiry test token",
			Fingerprint: utils.Ptr(fingerprint),
			Scopes:      "scan",
			ExpiryDate:  utils.Ptr(expiry),
		}
		require.NoError(t, db.Create(&pat).Error)
	}

	t.Run("returns a token whose expiry is in the future", func(t *testing.T) {
		createPAT("valid-fp", time.Now().Add(time.Hour))

		pat, found := patService.CheckForValidTokenByFingerprint(ctx, "valid-fp")

		require.True(t, found)
		assert.Equal(t, "valid-fp", *pat.Fingerprint)
	})

	t.Run("rejects a token whose expiry is in the past", func(t *testing.T) {
		createPAT("expired-fp", time.Now().Add(-time.Hour))

		_, found := patService.CheckForValidTokenByFingerprint(ctx, "expired-fp")

		require.False(t, found)
	})

	t.Run("rejects an unknown fingerprint", func(t *testing.T) {
		_, found := patService.CheckForValidTokenByFingerprint(ctx, "does-not-exist")

		require.False(t, found)
	})
}
