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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package utils

import "slices"

func Filter[T any](s []T, f func(T) bool) []T {
	// Pre-allocate with input length as capacity (worst case: all elements pass filter)
	r := make([]T, 0, len(s))
	for _, v := range s {
		if f(v) {
			r = append(r, v)
		}
	}
	return r
}

func MapType[New any, Old any](s []Old) []New {
	r := make([]New, len(s))
	for i, v := range s {
		r[i] = any(v).(New)
	}
	return r
}

func Map[T, U any](s []T, f func(T) U) []U {
	r := make([]U, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}

func DereferenceSlice[T any](s []*T) []T {
	r := make([]T, len(s))
	for i, v := range s {
		if v == nil {
			continue
		}
		r[i] = *v
	}
	return r
}

func Reduce[T, U any](s []T, f func(U, T) U, init U) U {
	r := init
	for _, v := range s {
		r = f(r, v)
	}
	return r
}

func Flat[T any](s [][]T) []T {
	res := make([]T, 0)
	for _, subslice := range s {
		res = append(res, subslice...)
	}
	return res
}

func Find[T any](s []T, f func(T) bool) (T, bool) {
	for _, v := range s {
		if f(v) {
			return v, true
		}
	}
	var t T
	return t, false
}

type CompareResult[T any] struct {
	OnlyInA []T
	OnlyInB []T
	InBoth  []T // returns the elements in A

	InBothB []T
}

func CompareSlices[T any, K comparable](a, b []T, serializer func(T) K) CompareResult[T] {
	res := CompareResult[T]{}
	inA := make(map[K]T)
	inB := make(map[K]T)

	for _, v := range b {
		inB[serializer(v)] = v
	}

	for _, v := range a {
		inA[serializer(v)] = v

		if _, ok := inB[serializer(v)]; ok {
			res.InBoth = append(res.InBoth, v)
			res.InBothB = append(res.InBothB, inB[serializer(v)])
		} else {
			res.OnlyInA = append(res.OnlyInA, v)
		}
	}

	for _, v := range b {
		if _, ok := inA[serializer(v)]; !ok {
			res.OnlyInB = append(res.OnlyInB, v)
		}
	}

	return res
}

func Any[T any](s []T, f func(T) bool) bool {
	for _, v := range s {
		if f(v) {
			return true
		}
	}
	return false
}

func All[T any](s []T, f func(T) bool) bool {
	for _, v := range s {
		if !f(v) {
			return false
		}
	}
	return true
}

func Some[T any](s []T, f func(T) bool) bool {
	return Any(s, f)
}

func UniqBy[T any, K comparable](s []T, f func(T) K) []T {
	seen := make(map[K]bool)
	res := make([]T, 0)
	for _, v := range s {
		if _, ok := seen[f(v)]; !ok {
			seen[f(v)] = true
			res = append(res, v)
		}
	}
	return res
}

func Contains[T comparable](s []T, el T) bool {
	return slices.Contains(s, el)
}

func ContainsAll[T comparable](s []T, needed []T) bool {
	return All(needed, func(n T) bool {
		return Contains(s, n)
	})
}
