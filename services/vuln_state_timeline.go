package services

import (
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/statemachine"
)

type vulnTimeline struct {
	pending []models.DependencyVuln
	visible []models.DependencyVuln
	applied []int
}

func newVulnTimeline(vulns []models.DependencyVuln) *vulnTimeline {
	pending := slices.Clone(vulns)
	for i := range pending {
		pending[i].State = ""
		pending[i].Events = slices.Clone(pending[i].Events)
		slices.SortStableFunc(pending[i].Events, func(a, b models.VulnEvent) int {
			return a.CreatedAt.Compare(b.CreatedAt)
		})
	}
	slices.SortStableFunc(pending, func(a, b models.DependencyVuln) int {
		return a.CreatedAt.Compare(b.CreatedAt)
	})
	return &vulnTimeline{pending: pending}
}

func (t *vulnTimeline) advanceTo(day time.Time) []models.DependencyVuln {
	for len(t.pending) > 0 && !t.pending[0].CreatedAt.After(day) {
		t.visible = append(t.visible, t.pending[0])
		t.applied = append(t.applied, 0)
		t.pending = t.pending[1:]
	}

	for i := range t.visible {
		events := t.visible[i].Events
		for t.applied[i] < len(events) && !events[t.applied[i]].CreatedAt.After(day) {
			statemachine.Apply(&t.visible[i], events[t.applied[i]])
			t.applied[i]++
		}
	}

	return t.visible
}
