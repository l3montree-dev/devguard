// Copyright (C) 2025 timbastin
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
package common

type Tabler interface {
	TableName() string
}

type ModelWriter[ID any, T Tabler, Tx any] interface {
	Create(tx Tx, t *T) error
	Save(tx Tx, t *T) error

	Delete(tx Tx, id ID) error
	Activate(tx Tx, id ID) error
}

type ModelReader[ID any, T Tabler] interface {
	Read(id ID) (T, error)
	List(ids []ID) ([]T, error)
	All() ([]T, error)
}

type BatchModelWriter[T Tabler, Tx any] interface {
	CreateBatch(tx Tx, ts []T) error
	SaveBatch(tx Tx, ts []T) error
}

type Transactioner[Tx any] interface {
	Transaction(func(tx Tx) error) error
	GetDB(tx Tx) Tx
	Begin() Tx
}

type Repository[ID any, T Tabler, Tx any] interface {
	ModelWriter[ID, T, Tx]
	ModelReader[ID, T]
	BatchModelWriter[T, Tx]
	Transactioner[Tx]
}
