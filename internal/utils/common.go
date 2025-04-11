// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"encoding/csv"
	"log/slog"
	"math"
	"runtime/debug"
	"strings"
)

func Ptr[T any](t T) *T {
	return &t
}

func RemovePrefixInsensitive(input string, prefix string) string {
	if strings.HasPrefix(strings.ToLower(input), strings.ToLower(prefix)) {
		return input[len(prefix):]
	}
	return input
}
func SafeDereference(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func EmptyThenNil(s string) *string {
	if s == "" {
		return nil
	}
	return Ptr(s)
}

func OrDefault[T any](val *T, def T) T {
	if val == nil {
		return def
	}
	return *val
}

func Or[T any](
	val *T,
	fallback *T,
) *T {
	if val == nil {
		return fallback
	}
	return val
}

func ReadCsvInChunks(reader *csv.Reader, chunkSize int, fn func(rows [][]string) error) (int, error) {
	count := 0

	chunk := make([][]string, 0, chunkSize)
	for {
		rows, err := reader.Read()
		if err != nil {
			break
		}
		count++

		chunk = append(chunk, rows)

		if len(chunk) == chunkSize {
			err := fn(chunk)
			if err != nil {
				return count, err
			}
			chunk = make([][]string, 0, chunkSize)
		}
	}

	if len(chunk) > 0 {
		return count, fn(chunk)
	}

	return count, nil
}

func ReadCsv(reader *csv.Reader, fn func(row []string) error) (int, error) {
	count := 0

	for {
		row, err := reader.Read()
		if err != nil {
			break
		}
		count++

		err = fn(row)
		if err != nil {
			return count, err
		}
	}

	return count, nil
}

func PrintBuildInformation() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				slog.Info("Build information", "revision", setting.Value)
			}
		}
	}
}

func CompareFirstTwoDecimals(a, b float64) bool {

	aRounded := math.Round(a*100) / 100
	bRounded := math.Round(b*100) / 100

	return aRounded == bRounded
}
