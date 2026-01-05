package repositories

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

func TestIsIgnorableUpsertError(t *testing.T) {
	t.Run("foreign_key_violation", func(t *testing.T) {
		pgErr := &pgconn.PgError{Code: "23503"}
		err := fmt.Errorf("%w", pgErr)
		// Use errors.As to ensure our helper recognizes PgError
		assert.True(t, isIgnorableUpsertError(pgErr))
		assert.True(t, isIgnorableUpsertError(err))
	})

	t.Run("parameter limit", func(t *testing.T) {
		pgErr := &pgconn.PgError{Code: "23505"}
		assert.True(t, isIgnorableUpsertError(pgErr))
	})
	t.Run("other error", func(t *testing.T) {
		assert.False(t, isIgnorableUpsertError(errors.New("some other error")))
		// Parameter limit message should not be considered ignorable
		assert.False(t, isIgnorableUpsertError(errors.New("extended protocol limited to 65535 parameters")))
	})
}
