package shared_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
)

func TestSortQuery(t *testing.T) {

	t.Run("should return a valid SQL query", func(t *testing.T) {
		q := shared.SortQuery{
			Field:    "single",
			Operator: "asc",
		}

		sql := q.SQL()

		assert.Equal(t, `"single" asc`, sql)
	})
}
