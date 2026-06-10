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
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetByFingerprint is the only PAT lookup on the real authentication path
// (session middleware → VerifyRequestSignature → getPubKeyAndUserIDUsingFingerprint).
// These tests pin its expiry enforcement: a valid token is returned, an expired
// one is rejected like a missing token, and an unknown fingerprint errors.
func TestPATGetByFingerprintEnforcesExpiry(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	repo := repositories.NewPATRepository(db)
	ctx := context.Background()

	createPAT := func(fingerprint string, expiry time.Time) {
		pat := models.PAT{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			PubKey:      "deadbeef",
			Description: "expiry test token",
			Fingerprint: fingerprint,
			Scopes:      "scan",
			ExpiryDate:  utils.Ptr(expiry),
		}
		require.NoError(t, db.Create(&pat).Error)
	}

	t.Run("returns a token whose expiry is in the future", func(t *testing.T) {
		createPAT("valid-fp", time.Now().Add(time.Hour))

		pat, err := repo.GetByFingerprint(ctx, nil, "valid-fp")

		require.NoError(t, err)
		assert.Equal(t, "valid-fp", pat.Fingerprint)
	})

	t.Run("rejects a token whose expiry is in the past", func(t *testing.T) {
		createPAT("expired-fp", time.Now().Add(-time.Hour))

		_, err := repo.GetByFingerprint(ctx, nil, "expired-fp")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")
	})

	t.Run("errors for an unknown fingerprint", func(t *testing.T) {
		_, err := repo.GetByFingerprint(ctx, nil, "does-not-exist")

		require.Error(t, err)
	})
}
