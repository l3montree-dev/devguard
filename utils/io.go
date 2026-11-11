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

package utils

import (
	"fmt"
	"io"
	"os"
)

func CreatePrivateTempDir(prefix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "devguard-"+prefix+"-")
	if err != nil {
		return "", nil, fmt.Errorf("could not create temp directory: %w", err)
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}

// unlike a bare io.LimitReader this fails instead of returning a silently truncated body
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds the maximum size of %d bytes", limit)
	}
	return data, nil
}
