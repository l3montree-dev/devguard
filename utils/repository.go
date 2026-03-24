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
package utils

import (
	"context"

	"gorm.io/gorm/clause"
)

type Tabler interface {
	TableName() string
}

type ModelWriter[ID any, T Tabler, Tx any] interface {
	Create(ctx context.Context, tx Tx, t *T) error
	Save(ctx context.Context, tx Tx, t *T) error
	Delete(ctx context.Context, tx Tx, id ID) error
	Activate(ctx context.Context, tx Tx, id ID) error
	CleanupOrphanedRecords(ctx context.Context) error
}

type ModelReader[ID any, T Tabler, Tx any] interface {
	Read(ctx context.Context, tx Tx, id ID) (T, error)
	List(ctx context.Context, tx Tx, ids []ID) ([]T, error)
	All(ctx context.Context, tx Tx) ([]T, error)
	Upsert(ctx context.Context, tx Tx, t *[]*T, conflictingColumns []clause.Column, updateOnly []string) error
}

type BatchModelWriter[T Tabler, Tx any] interface {
	CreateBatch(ctx context.Context, tx Tx, ts []T) error
	SaveBatch(ctx context.Context, tx Tx, ts []T) error
	DeleteBatch(ctx context.Context, tx Tx, ids []T) error
	SaveBatchBestEffort(ctx context.Context, tx Tx, ts []T) error
}

type Transactioner[Tx any] interface {
	Transaction(ctx context.Context, fn func(tx Tx) error) error
	GetDB(ctx context.Context, tx Tx) Tx
	Begin(ctx context.Context) Tx
}

type Repository[ID any, T Tabler, Tx any] interface {
	ModelWriter[ID, T, Tx]
	ModelReader[ID, T, Tx]
	BatchModelWriter[T, Tx]
	Transactioner[Tx]
}
