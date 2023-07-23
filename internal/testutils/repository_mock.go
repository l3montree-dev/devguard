// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
package testutils

type hasID[ID any] interface {
	GetID() ID
}

type MockRepository[ID comparable, T hasID[ID]] struct {
	Items []T
}

func NewMockRepository[ID comparable, T hasID[ID]]() *MockRepository[ID, T] {
	return &MockRepository[ID, T]{
		Items: make([]T, 0),
	}
}

func (m *MockRepository[ID, T]) Create(t *T) error {
	m.Items = append(m.Items, *t)
	return nil
}

func (m *MockRepository[ID, T]) Read(id ID) (T, error) {
	for _, item := range m.Items {
		if item.GetID() == id {
			return item, nil
		}
	}
	var t T
	return t, nil
}

func (m *MockRepository[ID, T]) Update(t T) error {
	for i, item := range m.Items {
		if item.GetID() == t.GetID() {
			m.Items[i] = t
			return nil
		}
	}
	return nil
}

func (m *MockRepository[ID, T]) Delete(id ID) error {
	for i, item := range m.Items {
		if item.GetID() == id {
			m.Items = append(m.Items[:i], m.Items[i+1:]...)
			return nil
		}
	}
	return nil
}
