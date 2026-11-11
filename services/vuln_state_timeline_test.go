package services

import (
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func statesByID(vulns []models.DependencyVuln) map[uuid.UUID]dtos.VulnState {
	states := map[uuid.UUID]dtos.VulnState{}
	for _, vuln := range vulns {
		states[vuln.ID] = vuln.State
	}
	return states
}

func replayStateAt(vuln models.DependencyVuln, day time.Time) dtos.VulnState {
	events := slices.Clone(vuln.Events)
	slices.SortStableFunc(events, func(a, b models.VulnEvent) int { return a.CreatedAt.Compare(b.CreatedAt) })

	vuln.State = ""
	for _, event := range events {
		if !event.CreatedAt.After(day) {
			statemachine.Apply(&vuln, event)
		}
	}
	return vuln.State
}

func TestVulnTimeline(t *testing.T) {
	at := func(day int) time.Time { return testDay.AddDate(0, 0, day).Add(12 * time.Hour) }
	endOf := func(day int) time.Time { return endOfDay(testDay.AddDate(0, 0, day)) }

	t.Run("a vuln is visible from the day it was created", func(t *testing.T) {
		id := uuid.New()
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(id, 1.0, at(2), newTestEvent(dtos.EventTypeDetected, at(2))),
		})

		assert.Empty(t, timeline.advanceTo(endOf(0)))
		assert.Empty(t, timeline.advanceTo(endOf(1)))
		assert.Equal(t, map[uuid.UUID]dtos.VulnState{id: dtos.VulnStateOpen}, statesByID(timeline.advanceTo(endOf(2))))
		assert.Equal(t, map[uuid.UUID]dtos.VulnState{id: dtos.VulnStateOpen}, statesByID(timeline.advanceTo(endOf(3))))
	})

	t.Run("applies an event on the day it happened and keeps the state afterwards", func(t *testing.T) {
		id := uuid.New()
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(id, 1.0, at(0),
				newTestEvent(dtos.EventTypeDetected, at(0)),
				newTestEvent(dtos.EventTypeFixed, at(2)),
				newTestEvent(dtos.EventTypeReopened, at(4)),
			),
		})

		expected := []dtos.VulnState{
			dtos.VulnStateOpen,
			dtos.VulnStateOpen,
			dtos.VulnStateFixed,
			dtos.VulnStateFixed,
			dtos.VulnStateOpen,
			dtos.VulnStateOpen,
		}
		for day, want := range expected {
			assert.Equal(t, want, timeline.advanceTo(endOf(day))[0].State, "day %d", day)
		}
	})

	t.Run("an event after the end of the day is not applied yet", func(t *testing.T) {
		id := uuid.New()
		lateInTheDay := endOf(0).Add(time.Second)
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(id, 1.0, at(0),
				newTestEvent(dtos.EventTypeDetected, at(0)),
				newTestEvent(dtos.EventTypeFixed, lateInTheDay),
			),
		})

		assert.Equal(t, dtos.VulnStateOpen, timeline.advanceTo(endOf(0))[0].State)
		assert.Equal(t, dtos.VulnStateFixed, timeline.advanceTo(endOf(1))[0].State)
	})

	t.Run("an event exactly at the end of the day is applied that day", func(t *testing.T) {
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(uuid.New(), 1.0, at(0),
				newTestEvent(dtos.EventTypeDetected, at(0)),
				newTestEvent(dtos.EventTypeFixed, endOf(0)),
			),
		})

		assert.Equal(t, dtos.VulnStateFixed, timeline.advanceTo(endOf(0))[0].State)
	})

	t.Run("a detected event does not reopen a fixed vuln", func(t *testing.T) {
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(uuid.New(), 1.0, at(0),
				newTestEvent(dtos.EventTypeDetected, at(0)),
				newTestEvent(dtos.EventTypeFixed, at(1)),
				newTestEvent(dtos.EventTypeDetected, at(2)),
			),
		})

		assert.Equal(t, dtos.VulnStateFixed, timeline.advanceTo(endOf(1))[0].State)
		assert.Equal(t, dtos.VulnStateFixed, timeline.advanceTo(endOf(2))[0].State)
	})

	t.Run("a persisted state is ignored and only the events decide", func(t *testing.T) {
		vuln := newTestTimelineVuln(uuid.New(), 1.0, at(0), newTestEvent(dtos.EventTypeDetected, at(0)))
		vuln.State = dtos.VulnStateFixed

		timeline := newVulnTimeline([]models.DependencyVuln{vuln})

		assert.Equal(t, dtos.VulnStateOpen, timeline.advanceTo(endOf(0))[0].State)
	})

	t.Run("a vuln without events is visible without a state", func(t *testing.T) {
		timeline := newVulnTimeline([]models.DependencyVuln{newTestTimelineVuln(uuid.New(), 1.0, at(0))})

		visible := timeline.advanceTo(endOf(0))
		require.Len(t, visible, 1)
		assert.Equal(t, dtos.VulnState(""), visible[0].State)
	})

	t.Run("jumping over days applies every skipped event in order", func(t *testing.T) {
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(uuid.New(), 1.0, at(0),
				newTestEvent(dtos.EventTypeDetected, at(0)),
				newTestEvent(dtos.EventTypeFixed, at(1)),
				newTestEvent(dtos.EventTypeReopened, at(2)),
				newTestEvent(dtos.EventTypeAccepted, at(3)),
			),
		})

		assert.Equal(t, dtos.VulnStateAccepted, timeline.advanceTo(endOf(5))[0].State)
	})

	t.Run("sorts vulns and events that are not ordered", func(t *testing.T) {
		first, second := uuid.New(), uuid.New()
		timeline := newVulnTimeline([]models.DependencyVuln{
			newTestTimelineVuln(second, 1.0, at(1), newTestEvent(dtos.EventTypeDetected, at(1))),
			newTestTimelineVuln(first, 1.0, at(0),
				newTestEvent(dtos.EventTypeFixed, at(1)),
				newTestEvent(dtos.EventTypeDetected, at(0)),
			),
		})

		assert.Equal(t, map[uuid.UUID]dtos.VulnState{first: dtos.VulnStateOpen}, statesByID(timeline.advanceTo(endOf(0))))
		assert.Equal(t, map[uuid.UUID]dtos.VulnState{first: dtos.VulnStateFixed, second: dtos.VulnStateOpen}, statesByID(timeline.advanceTo(endOf(1))))
	})

	t.Run("does not change the vulns it was created from", func(t *testing.T) {
		vuln := newTestTimelineVuln(uuid.New(), 1.0, at(0),
			newTestEvent(dtos.EventTypeFixed, at(1)),
			newTestEvent(dtos.EventTypeDetected, at(0)),
		)
		vuln.State = dtos.VulnStateAccepted
		vulns := []models.DependencyVuln{vuln}

		timeline := newVulnTimeline(vulns)
		timeline.advanceTo(endOf(3))

		assert.Equal(t, dtos.VulnStateAccepted, vulns[0].State)
		assert.Equal(t, dtos.EventTypeFixed, vulns[0].Events[0].Type)
		assert.Equal(t, dtos.EventTypeDetected, vulns[0].Events[1].Type)
	})

	t.Run("no vulns, no result", func(t *testing.T) {
		assert.Empty(t, newVulnTimeline(nil).advanceTo(endOf(0)))
	})

	t.Run("matches a replay of all events up to that day for every day", func(t *testing.T) {
		random := rand.New(rand.NewSource(7))
		eventTypes := []dtos.VulnEventType{
			dtos.EventTypeDetected,
			dtos.EventTypeFixed,
			dtos.EventTypeReopened,
			dtos.EventTypeAccepted,
			dtos.EventTypeFalsePositive,
			dtos.EventTypeComment,
			dtos.EventTypeRawRiskAssessmentUpdated,
		}

		const days = 30
		vulns := make([]models.DependencyVuln, 0, 60)
		for i := 0; i < 60; i++ {
			events := make([]models.VulnEvent, random.Intn(8))
			for j := range events {
				events[j] = newTestEvent(eventTypes[random.Intn(len(eventTypes))], testDay.Add(time.Duration(random.Intn(days*24))*time.Hour))
			}
			vulns = append(vulns, newTestTimelineVuln(uuid.New(), 1.0, testDay.Add(time.Duration(random.Intn(20*24))*time.Hour), events...))
		}

		timeline := newVulnTimeline(vulns)
		for day := 0; day <= days; day++ {
			want := map[uuid.UUID]dtos.VulnState{}
			for _, vuln := range vulns {
				if !vuln.CreatedAt.After(endOf(day)) {
					want[vuln.ID] = replayStateAt(vuln, endOf(day))
				}
			}

			assert.Equal(t, want, statesByID(timeline.advanceTo(endOf(day))), "day %d", day)
		}
	})
}
