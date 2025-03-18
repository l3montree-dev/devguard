package core_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/stretchr/testify/assert"
)

func TestSortQuery(t *testing.T) {

	t.Run("should return a valid SQL query", func(t *testing.T) {
		q := core.SortQuery{
			Field:    "single",
			Operator: "asc",
		}

		sql := q.SQL()

		assert.Equal(t, `"single" asc`, sql)
	})

	t.Run("should snake case the field", func(t *testing.T) {
		q := core.SortQuery{
			Field:    "camelCase",
			Operator: "asc",
		}

		sql := q.SQL()

		assert.Equal(t, `"camel_case" asc`, sql)
	})

	t.Run("should snake case relation fields", func(t *testing.T) {
		q := core.SortQuery{
			Field:    "relationField.camelCase",
			Operator: "desc",
		}

		sql := q.SQL()

		assert.Equal(t, `"relation_field"."camel_case" desc NULLS LAST`, sql)
	})

	t.Run("should respect nested relation fields", func(t *testing.T) {

		q := core.SortQuery{
			Field:    "component.project.scoreCardScore",
			Operator: "asc",
		}

		sql := q.SQL()

		assert.Equal(t, `"Component__Project"."score_card_score" asc`, sql)
	})
}
