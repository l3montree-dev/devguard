// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package utils

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
)

func HashString(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

// HashToUUID hashes the input string with SHA-256 and returns the first 128 bits as a UUID.
func HashToUUID(s string) uuid.UUID {
	hash := sha256.Sum256([]byte(s))
	// Take first 16 bytes (128 bits) of SHA-256 hash
	id, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(fmt.Sprintf("failed to create UUID from hash bytes: %v", err))
	}
	return id
}
