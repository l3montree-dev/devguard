package vulndb

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterTablesToCleanup(t *testing.T) {
	now := time.Now().Unix()

	t.Run("typical", func(t *testing.T) {
		old := fmt.Sprintf("cves_backup_%d", now-25*3600)      // 25 hours ago -> should be cleaned
		recent := fmt.Sprintf("cves_backup_%d", now-23*3600)   // 23 hours ago -> should NOT be cleaned
		boundary := fmt.Sprintf("cves_backup_%d", now-24*3600) // exactly 24 hours ago -> not cleaned because comparison is <
		shadowOld := fmt.Sprintf("exploits_shadow_%d", now-100*3600)

		input := []string{recent, "cves_backup_no_timestamp", old, boundary, "cves_backup_abcdef", shadowOld}
		got := filterTablesToCleanup(input, 24)
		// Use ElementsMatch to avoid brittle ordering assumptions
		assert.ElementsMatch(t, []string{old, shadowOld}, got)
	})

	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, filterTablesToCleanup([]string{}, 24))
	})

	t.Run("malformed_only", func(t *testing.T) {
		input := []string{"just_a_table", "another_table_", "table_backup_abc"}
		assert.Empty(t, filterTablesToCleanup(input, 1))
	})

	t.Run("boundary_exact_24_hours", func(t *testing.T) {
		boundary := fmt.Sprintf("cves_backup_%d", now-24*3600)
		assert.Empty(t, filterTablesToCleanup([]string{boundary}, 24))
	})

	t.Run("non_numeric_timestamp", func(t *testing.T) {
		nonnumeric := "cves_backup_abcdef"
		assert.Empty(t, filterTablesToCleanup([]string{nonnumeric}, 1))
	})
}
