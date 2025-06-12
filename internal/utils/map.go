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

func Mapper[Key comparable, T any](s []T, f func(T) Key) map[Key]T {
	res := make(map[Key]T)
	for _, v := range s {
		res[f(v)] = v
	}

	return res
}

func Values[K comparable, T any](m map[K]T) []T {
	res := make([]T, 0, len(m))
	for _, v := range m {
		res = append(res, v)
	}
	return res
}
