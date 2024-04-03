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

type concurrentResult struct {
	index int
	value any
}

func Concurrently(fns ...func() any) []any {
	results := make([]concurrentResult, len(fns))
	ch := make(chan concurrentResult, len(fns))
	for i, fn := range fns {
		go func(i int, fn func() any) {
			ch <- concurrentResult{i, fn()}
		}(i, fn)
	}
	for i := 0; i < len(fns); i++ {
		results[i] = <-ch
	}

	res := make([]any, len(fns))
	for _, r := range results {
		res[r.index] = r.value
	}

	return res
}
