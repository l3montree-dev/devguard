package services

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestReplayHistory(t *testing.T) {
	t.Run("accumulates the open vulns from the stored diffs day by day", func(t *testing.T) {
		artifactName := "TestArtifact"
		assetVersionName := "Test"
		assetID := uuid.New()

		today := time.Now().UTC()
		startDay := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -89)
		dayBeforeStart := startDay.AddDate(0, 0, -1)

		vulnsByID := map[uuid.UUID]models.DependencyVuln{}
		riskHistory := make([]models.ArtifactRiskHistory, 90)
		vulnIDStrings := make([]string, 90)

		for i := 0; i < 90; i++ {
			id := uuid.New()
			vulnIDStrings[i] = id.String()
			vulnsByID[id] = models.DependencyVuln{
				RiskAssessment: new(1.0),
				Vulnerability: models.Vulnerability{
					ID: id,
				},
				CVE: &models.CVE{
					CVSS: 2.0,
				},
			}

			riskHistory[i] = models.ArtifactRiskHistory{
				ArtifactName:     artifactName,
				AssetVersionName: assetVersionName,
				AssetID:          assetID,
				History: models.History{
					Day: startDay.AddDate(0, 0, i),
					Distribution: models.Distribution{
						DiffAddedDependencyVulns: []string{id.String()},
					},
				},
			}
		}

		statisticsRepository := mocks.NewStatisticsRepository(t)
		assetRiskHistoryRepository := mocks.NewArtifactRiskHistoryRepository(t)
		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		assetVersionRepository := mocks.NewAssetVersionRepository(t)

		statisticsService := NewStatisticsService(statisticsRepository, assetRiskHistoryRepository, dependencyVulnRepository, assetVersionRepository)

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, dayBeforeStart).Return(nil, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, dayBeforeStart).Return([]models.ArtifactRiskHistory{}, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, startDay, today).Return(riskHistory, nil)

		mockListWithCVE(dependencyVulnRepository, vulnsByID)

		replayedHistory, err := statisticsService.replayRiskHistoryFromDiffs(context.Background(), &artifactName, assetVersionName, assetID, startDay, today)
		assert.NoError(t, err)
		assert.Len(t, replayedHistory, 90)
		for index, historyItem := range replayedHistory {
			assert.ElementsMatch(t, vulnIDStrings[:index+1], historyItem.Low)
		}
	})

	t.Run("starts from the empty root when there is no snapshot", func(t *testing.T) {
		artifactName := "TestArtifact"
		assetVersionName := "Test"
		assetID := uuid.New()

		startDay := testDay
		end := startDay.AddDate(0, 0, 2)
		dayBeforeStart := startDay.AddDate(0, 0, -1)

		a, b, c := uuid.New(), uuid.New(), uuid.New()
		vulnsByID := map[uuid.UUID]models.DependencyVuln{
			a: newTestDependencyVuln(a, 1.0),
			b: newTestDependencyVuln(b, 1.0),
			c: newTestDependencyVuln(c, 1.0),
		}

		statisticsService, assetRiskHistoryRepository, dependencyVulnRepository := newTestStatisticsService(t)

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, dayBeforeStart).Return(nil, nil)

		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, dayBeforeStart).Return([]models.ArtifactRiskHistory{
			newDiffRow(startDay.AddDate(0, 0, -3), []string{a.String(), b.String()}, nil),
			newDiffRow(startDay.AddDate(0, 0, -2), nil, []string{a.String()}),
		}, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, startDay, end).Return([]models.ArtifactRiskHistory{
			newDiffRow(startDay, []string{c.String()}, nil),
			newDiffRow(startDay.AddDate(0, 0, 1), nil, []string{b.String()}),
			newDiffRow(startDay.AddDate(0, 0, 2), nil, nil),
		}, nil)
		mockListWithCVE(dependencyVulnRepository, vulnsByID)

		replayedHistory, err := statisticsService.replayRiskHistoryFromDiffs(context.Background(), &artifactName, assetVersionName, assetID, startDay, end)
		assert.NoError(t, err)
		if assert.Len(t, replayedHistory, 3) {
			assert.ElementsMatch(t, []string{b.String(), c.String()}, replayedHistory[0].Low)
			assert.ElementsMatch(t, []string{c.String()}, replayedHistory[1].Low)
			assert.ElementsMatch(t, []string{c.String()}, replayedHistory[2].Low)
		}
	})

	t.Run("starts from the snapshot when one exists", func(t *testing.T) {
		artifactName := "TestArtifact"
		assetVersionName := "Test"
		assetID := uuid.New()

		startDay := testDay
		end := startDay.AddDate(0, 0, 1)
		dayBeforeStart := startDay.AddDate(0, 0, -1)

		a, b, c, d := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		vulnsByID := map[uuid.UUID]models.DependencyVuln{
			a: newTestDependencyVuln(a, 1.0),
			b: newTestDependencyVuln(b, 9.5),
			c: newTestDependencyVuln(c, 1.0),
			d: newTestDependencyVuln(d, 1.0),
		}

		snapshot := models.ArtifactRiskHistory{
			ArtifactName:     artifactName,
			AssetVersionName: assetVersionName,
			AssetID:          assetID,
			History: models.History{
				Day: startDay.AddDate(0, 0, -5),
				Distribution: models.Distribution{
					Low:      []string{a.String()},
					Critical: []string{b.String()},
				},
			},
		}

		statisticsService, assetRiskHistoryRepository, dependencyVulnRepository := newTestStatisticsService(t)

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, dayBeforeStart).Return(&snapshot, nil)

		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, snapshot.Day, dayBeforeStart).Return([]models.ArtifactRiskHistory{
			newDiffRow(startDay.AddDate(0, 0, -3), []string{c.String()}, []string{a.String()}),
		}, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, startDay, end).Return([]models.ArtifactRiskHistory{
			newDiffRow(startDay, []string{d.String()}, nil),
			newDiffRow(startDay.AddDate(0, 0, 1), nil, nil),
		}, nil)
		mockListWithCVE(dependencyVulnRepository, vulnsByID)

		replayedHistory, err := statisticsService.replayRiskHistoryFromDiffs(context.Background(), &artifactName, assetVersionName, assetID, startDay, end)
		assert.NoError(t, err)
		if assert.Len(t, replayedHistory, 2) {
			for _, historyItem := range replayedHistory {
				assert.ElementsMatch(t, []string{c.String(), d.String()}, historyItem.Low)
				assert.ElementsMatch(t, []string{b.String()}, historyItem.Critical)
			}
		}
	})

	t.Run("normalizes the start to the beginning of its UTC day", func(t *testing.T) {
		artifactName := "TestArtifact"
		assetVersionName := "Test"
		assetID := uuid.New()

		// 01:30 at UTC+3 is still the day before in UTC
		start := time.Date(2025, time.March, 1, 1, 30, 0, 0, time.FixedZone("UTC+3", 3*60*60))
		startDay := time.Date(2025, time.February, 28, 0, 0, 0, 0, time.UTC)
		end := startDay.AddDate(0, 0, 1)

		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, startDay.AddDate(0, 0, -1)).Return(nil, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, startDay.AddDate(0, 0, -1)).Return([]models.ArtifactRiskHistory{}, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, startDay, end).Return([]models.ArtifactRiskHistory{}, nil)

		replayedHistory, err := statisticsService.replayRiskHistoryFromDiffs(context.Background(), &artifactName, assetVersionName, assetID, start, end)
		assert.NoError(t, err)
		assert.Empty(t, replayedHistory)
	})
}

func TestOpenVulnIDsAt(t *testing.T) {
	artifactName := "TestArtifact"
	assetVersionName := "Test"
	assetID := uuid.New()
	at := testDay

	t.Run("is empty without a snapshot and without diffs", func(t *testing.T) {
		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, at).Return(nil, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, at).Return([]models.ArtifactRiskHistory{}, nil)

		openVulnIDs, err := statisticsService.openVulnIDsAt(context.Background(), &artifactName, assetVersionName, assetID, at)
		assert.NoError(t, err)
		assert.Empty(t, openVulnIDs)
	})

	t.Run("replays every stored diff from the empty root when there is no snapshot", func(t *testing.T) {
		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)
		a, b, c := uuid.NewString(), uuid.NewString(), uuid.NewString()

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, at).Return(nil, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, at).Return([]models.ArtifactRiskHistory{
			newDiffRow(at.AddDate(0, 0, -2), []string{a, b}, nil),
			newDiffRow(at.AddDate(0, 0, -1), []string{c}, []string{a}),
		}, nil)

		openVulnIDs, err := statisticsService.openVulnIDsAt(context.Background(), &artifactName, assetVersionName, assetID, at)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{b, c}, slices.Collect(maps.Keys(openVulnIDs)))
	})

	t.Run("seeds from the snapshot and only replays the diffs since its day", func(t *testing.T) {
		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)
		low, medium, high, critical, openedLater, notInRiskBuckets := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()

		snapshot := models.ArtifactRiskHistory{
			ArtifactName:     artifactName,
			AssetVersionName: assetVersionName,
			AssetID:          assetID,
			History: models.History{
				Day: at.AddDate(0, 0, -10),
				Distribution: models.Distribution{
					Low:      []string{low},
					Medium:   []string{medium},
					High:     []string{high},
					Critical: []string{critical},
					// every open vuln is in exactly one of the risk buckets, the other distributions are not used to rebuild the set
					FixableLow: []string{notInRiskBuckets},
					LowCVSS:    []string{notInRiskBuckets},
				},
			},
		}

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, at).Return(&snapshot, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, snapshot.Day, at).Return([]models.ArtifactRiskHistory{
			newDiffRow(at.AddDate(0, 0, -5), []string{openedLater}, []string{medium}),
		}, nil)

		openVulnIDs, err := statisticsService.openVulnIDsAt(context.Background(), &artifactName, assetVersionName, assetID, at)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{low, high, critical, openedLater}, slices.Collect(maps.Keys(openVulnIDs)))
	})

	t.Run("returns the error of the snapshot lookup without loading any diffs", func(t *testing.T) {
		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)
		snapshotErr := errors.New("snapshot lookup failed")

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, at).Return(nil, snapshotErr)

		openVulnIDs, err := statisticsService.openVulnIDsAt(context.Background(), &artifactName, assetVersionName, assetID, at)
		assert.ErrorIs(t, err, snapshotErr)
		assert.Nil(t, openVulnIDs)
	})

	t.Run("returns the error of the diff lookup", func(t *testing.T) {
		statisticsService, assetRiskHistoryRepository, _ := newTestStatisticsService(t)
		historyErr := errors.New("history lookup failed")

		assetRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, at).Return(nil, nil)
		assetRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &artifactName, assetVersionName, assetID, time.Time{}, at).Return(nil, historyErr)

		openVulnIDs, err := statisticsService.openVulnIDsAt(context.Background(), &artifactName, assetVersionName, assetID, at)
		assert.ErrorIs(t, err, historyErr)
		assert.Nil(t, openVulnIDs)
	})
}

var testDay = time.Date(2025, time.March, 1, 0, 0, 0, 0, time.UTC)

func newTestStatisticsService(t *testing.T) (*statisticsService, *mocks.ArtifactRiskHistoryRepository, *mocks.DependencyVulnRepository) {
	t.Helper()

	assetRiskHistoryRepository := mocks.NewArtifactRiskHistoryRepository(t)
	dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
	statisticsService := NewStatisticsService(mocks.NewStatisticsRepository(t), assetRiskHistoryRepository, dependencyVulnRepository, mocks.NewAssetVersionRepository(t))

	return statisticsService, assetRiskHistoryRepository, dependencyVulnRepository
}

func newTestDependencyVuln(id uuid.UUID, risk float64) models.DependencyVuln {
	return models.DependencyVuln{
		RiskAssessment: &risk,
		Vulnerability:  models.Vulnerability{ID: id},
		CVE:            &models.CVE{CVSS: 2.0},
	}
}

func newDiffRow(day time.Time, added, removed []string) models.ArtifactRiskHistory {
	return models.ArtifactRiskHistory{
		History: models.History{
			Day: day,
			Distribution: models.Distribution{
				DiffAddedDependencyVulns:   added,
				DiffRemovedDependencyVulns: removed,
			},
		},
	}
}

// mockListWithCVE answers ListWithCVE by looking the requested IDs up, because the service collects them from a map in random order
func mockListWithCVE(dependencyVulnRepository *mocks.DependencyVulnRepository, vulnsByID map[uuid.UUID]models.DependencyVuln) {
	dependencyVulnRepository.EXPECT().ListWithCVE(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ shared.DB, ids []uuid.UUID) ([]models.DependencyVuln, error) {
			vulns := make([]models.DependencyVuln, 0, len(ids))
			for _, id := range ids {
				vulns = append(vulns, vulnsByID[id])
			}
			return vulns, nil
		})
}

func TestIsSnapShotDay(t *testing.T) {
	statisticsService, _, _ := newTestStatisticsService(t)

	// 2025-03-13 is day 20160 since the epoch, which is 224 * 90
	snapshotDay := time.Date(2025, time.March, 13, 0, 0, 0, 0, time.UTC)

	t.Run("every 90th day since the epoch is a snapshot day", func(t *testing.T) {
		assert.True(t, statisticsService.isSnapShotDay(time.Unix(0, 0)))
		assert.True(t, statisticsService.isSnapShotDay(snapshotDay))
		assert.True(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, 90)))
		assert.True(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, -90)))
		assert.True(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, -90*2)))
		assert.True(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, 90*67)))
	})

	t.Run("the days around a snapshot day are not", func(t *testing.T) {
		assert.False(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, -1)))
		assert.False(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, 1)))
		assert.False(t, statisticsService.isSnapShotDay(snapshotDay.AddDate(0, 0, 89)))
	})

	t.Run("the whole UTC day counts, not only its first second", func(t *testing.T) {
		assert.True(t, statisticsService.isSnapShotDay(endOfDay(snapshotDay)))
	})

	t.Run("uses the UTC day and not the day in the timezone of the given time", func(t *testing.T) {
		// 01:00 at UTC+3 on March 13th is still March 12th in UTC
		assert.False(t, statisticsService.isSnapShotDay(time.Date(2025, time.March, 13, 1, 0, 0, 0, time.FixedZone("UTC+3", 3*60*60))))
		// 22:00 at UTC-5 on March 12th is already March 13th in UTC
		assert.True(t, statisticsService.isSnapShotDay(time.Date(2025, time.March, 12, 22, 0, 0, 0, time.FixedZone("UTC-5", -5*60*60))))
	})
}

func TestRebuildArtifactRiskHistory(t *testing.T) {
	t.Run("stores one row per day with the counts and the diff to the previous day", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		begin := testDay
		end := testDay.AddDate(0, 0, 2)

		pre, a, b, f := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		at := func(day int) time.Time { return begin.AddDate(0, 0, day).Add(12 * time.Hour) }

		// pre was already open before the window, so it is the starting point for the diff of the first day
		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, []models.ArtifactRiskHistory{
			newDiffRow(begin.AddDate(0, 0, -4), []string{pre.String()}, nil),
		})
		env.expectVulns(
			newTestTimelineVuln(pre, 5.0, longBeforeTestDay, newTestEvent(dtos.EventTypeDetected, longBeforeTestDay), newTestEvent(dtos.EventTypeFixed, at(1))),
			newTestTimelineVuln(a, 8.0, at(0), newTestEvent(dtos.EventTypeDetected, at(0))),
			newTestTimelineVuln(b, 1.0, at(1), newTestEvent(dtos.EventTypeDetected, at(1))),
			newTestTimelineVuln(f, 2.0, at(0), newTestEvent(dtos.EventTypeDetected, at(0)), newTestEvent(dtos.EventTypeFixed, at(0).Add(time.Hour))),
		)
		env.expectLastHistoryUpdateSaved()

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, end)
		assert.NoError(t, err)

		expected := []struct {
			open, fixed               int
			sumOpen, avgOpen, maxOpen float64
			sumClosed                 float64
			diffAdded, diffRemoved    []string
		}{
			{open: 2, fixed: 1, sumOpen: 13, avgOpen: 6.5, maxOpen: 8, sumClosed: 2, diffAdded: []string{a.String()}, diffRemoved: []string{}},
			{open: 2, fixed: 2, sumOpen: 9, avgOpen: 4.5, maxOpen: 8, sumClosed: 7, diffAdded: []string{b.String()}, diffRemoved: []string{pre.String()}},
			{open: 2, fixed: 2, sumOpen: 9, avgOpen: 4.5, maxOpen: 8, sumClosed: 7, diffAdded: []string{}, diffRemoved: []string{}},
		}
		require.Len(t, env.saved, len(expected))
		for i, want := range expected {
			row := env.saved[i]

			assert.Equal(t, endOfDay(begin.AddDate(0, 0, i)), row.Day)
			assert.Equal(t, env.artifact.ArtifactName, row.ArtifactName)
			assert.Equal(t, env.artifact.AssetVersionName, row.AssetVersionName)
			assert.Equal(t, env.artifact.AssetID, row.AssetID)

			assert.Equal(t, want.open, row.OpenDependencyVulns, "day %d", i)
			assert.Equal(t, want.fixed, row.FixedDependencyVulns, "day %d", i)
			assert.Equal(t, want.sumOpen, row.SumOpenRisk, "day %d", i)
			assert.Equal(t, want.avgOpen, row.AvgOpenRisk, "day %d", i)
			assert.Equal(t, want.maxOpen, row.MaxOpenRisk, "day %d", i)
			assert.Equal(t, want.sumClosed, row.SumClosedRisk, "day %d", i)
			assert.ElementsMatch(t, want.diffAdded, row.DiffAddedDependencyVulns, "day %d", i)
			assert.ElementsMatch(t, want.diffRemoved, row.DiffRemovedDependencyVulns, "day %d", i)

			// none of these is a snapshot day, so the full distribution is not stored
			assert.False(t, env.service.isSnapShotDay(row.Day), "day %d", i)
			for name, column := range snapshotColumnsOf(row.Distribution) {
				assert.Nil(t, column, "%s on day %d", name, i)
			}
		}

		require.NotNil(t, env.artifact.LastHistoryUpdate)
		assert.Equal(t, endOfDay(end), *env.artifact.LastHistoryUpdate)
	})

	t.Run("stores the full distribution only on the snapshot day", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		snapshotDay := firstSnapshotDayFrom(env.service, testDay)
		begin := snapshotDay.AddDate(0, 0, -1)
		end := snapshotDay.AddDate(0, 0, 1)

		low, high, critical, fixed := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		openVulns := []models.DependencyVuln{
			newTestOpenVuln(low, 1.0),
			newTestOpenVuln(high, 7.5),
			newTestOpenVuln(critical, 9.5),
			newTestFixedVuln(fixed, 9.5),
		}
		openVulns[1].CVE.CVSS = 7.5
		openVulns[2].CVE.CVSS = 9.8

		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.expectVulns(openVulns...)
		env.expectLastHistoryUpdateSaved()

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, end)
		assert.NoError(t, err)
		require.Len(t, env.saved, 3)

		for _, row := range []models.ArtifactRiskHistory{env.saved[0], env.saved[2]} {
			assert.False(t, env.service.isSnapShotDay(row.Day))
			for name, column := range snapshotColumnsOf(row.Distribution) {
				assert.Nil(t, column, "%s on %s", name, row.Day)
			}
		}

		snapshot := env.saved[1]
		assert.True(t, env.service.isSnapShotDay(snapshot.Day))
		for name, column := range snapshotColumnsOf(snapshot.Distribution) {
			assert.NotNil(t, column, name)
		}
		assert.ElementsMatch(t, []string{low.String()}, snapshot.Low)
		assert.Empty(t, snapshot.Medium)
		assert.ElementsMatch(t, []string{high.String()}, snapshot.High)
		assert.ElementsMatch(t, []string{critical.String()}, snapshot.Critical)
		assert.ElementsMatch(t, []string{low.String()}, snapshot.LowCVSS)
		assert.ElementsMatch(t, []string{high.String()}, snapshot.HighCVSS)
		assert.ElementsMatch(t, []string{critical.String()}, snapshot.CriticalCVSS)

		// the diffs are stored on every day, snapshot or not
		assert.ElementsMatch(t, []string{low.String(), high.String(), critical.String()}, env.saved[0].DiffAddedDependencyVulns)
		assert.Empty(t, snapshot.DiffAddedDependencyVulns)
		assert.Empty(t, snapshot.DiffRemovedDependencyVulns)
	})

	t.Run("a snapshot day without open vulns still stores empty, non-null columns", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		snapshotDay := firstSnapshotDayFrom(env.service, testDay)

		env.expectStartState(endOfDay(snapshotDay).AddDate(0, 0, -1), nil, nil)
		env.expectVulns()
		env.expectLastHistoryUpdateSaved()

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, snapshotDay, snapshotDay)
		assert.NoError(t, err)
		require.Len(t, env.saved, 1)

		// the repository recognizes a snapshot row by any of these columns being NOT NULL,
		// a nil slice would be stored as NULL and the day would never be found as a snapshot
		columns := snapshotColumnsOf(env.saved[0].Distribution)
		assert.NotEmpty(t, columns)
		for name, column := range columns {
			assert.NotNil(t, column, name)
			assert.Empty(t, column, name)
		}
	})

	t.Run("a window starting on a snapshot day continues from the previous snapshot, not from its own", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		snapshotDay := firstSnapshotDayFrom(env.service, testDay)

		carriedOver, opened := uuid.New(), uuid.New()
		previousSnapshot := models.ArtifactRiskHistory{
			History: models.History{
				Day: endOfDay(snapshotDay.AddDate(0, 0, -snapshotFrequence)),
				Distribution: models.Distribution{
					Low: []string{carriedOver.String()},
				},
			},
		}

		env.expectStartState(endOfDay(snapshotDay).AddDate(0, 0, -1), &previousSnapshot, nil)
		env.expectVulns(newTestOpenVuln(carriedOver, 1.0), newTestOpenVuln(opened, 1.0))
		env.expectLastHistoryUpdateSaved()

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, snapshotDay, snapshotDay)
		assert.NoError(t, err)
		require.Len(t, env.saved, 1)

		assert.ElementsMatch(t, []string{opened.String()}, env.saved[0].DiffAddedDependencyVulns)
		assert.Empty(t, env.saved[0].DiffRemovedDependencyVulns)
		assert.ElementsMatch(t, []string{carriedOver.String(), opened.String()}, env.saved[0].Low)
	})

	t.Run("a rebuild starting the day after a snapshot day continues from the snapshot stored on it", func(t *testing.T) {
		low, critical, fresh := uuid.New(), uuid.New(), uuid.New()

		// first rebuild: writes the snapshot day
		first := newRebuildTestEnv(t)
		snapshotDay := firstSnapshotDayFrom(first.service, testDay)
		nextDay := snapshotDay.AddDate(0, 0, 1)
		onNextDay := nextDay.Add(12 * time.Hour)

		vulns := []models.DependencyVuln{
			newTestOpenVuln(low, 1.0),
			newTestTimelineVuln(critical, 9.5, longBeforeTestDay, newTestEvent(dtos.EventTypeDetected, longBeforeTestDay), newTestEvent(dtos.EventTypeFixed, onNextDay)),
			newTestTimelineVuln(fresh, 1.0, onNextDay, newTestEvent(dtos.EventTypeDetected, onNextDay)),
		}

		first.expectStartState(endOfDay(snapshotDay).AddDate(0, 0, -1), nil, nil)
		first.expectVulns(vulns...)
		first.expectLastHistoryUpdateSaved()

		err := first.service.RebuildArtifactRiskHistory(context.Background(), nil, first.artifact, first.artifact.AssetID, snapshotDay, snapshotDay)
		require.NoError(t, err)
		require.Len(t, first.saved, 1)
		snapshotRow := first.saved[0]

		// second rebuild: starts the day after and has to find what the first one wrote
		second := newRebuildTestEnv(t)

		second.expectStartState(endOfDay(nextDay).AddDate(0, 0, -1), &snapshotRow, []models.ArtifactRiskHistory{snapshotRow})
		second.expectVulns(vulns...)
		second.expectLastHistoryUpdateSaved()

		err = second.service.RebuildArtifactRiskHistory(context.Background(), nil, second.artifact, second.artifact.AssetID, nextDay, nextDay)
		assert.NoError(t, err)
		require.Len(t, second.saved, 1)

		// low stayed open and is not reported again
		assert.ElementsMatch(t, []string{fresh.String()}, second.saved[0].DiffAddedDependencyVulns)
		assert.ElementsMatch(t, []string{critical.String()}, second.saved[0].DiffRemovedDependencyVulns)
	})

	t.Run("returns the error of the vuln lookup without saving anything", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		begin := testDay
		lookupErr := errors.New("vuln lookup failed")

		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.statisticsRepository.EXPECT().GetDependencyVulnsWithEvents(mock.Anything, mock.Anything, env.artifact.ArtifactName, env.artifact.AssetVersionName, env.artifact.AssetID).
			Return(nil, lookupErr)

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, begin.AddDate(0, 0, 2))
		assert.ErrorIs(t, err, lookupErr)
		assert.Empty(t, env.saved)
		assert.Nil(t, env.artifact.LastHistoryUpdate)
	})

	t.Run("returns the error of saving the rows and does not remember an update", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		begin := testDay
		saveErr := errors.New("saving failed")

		env.saveErr = saveErr
		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.expectVulns(newTestOpenVuln(uuid.New(), 1.0))

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, begin.AddDate(0, 0, 2))
		assert.ErrorIs(t, err, saveErr)
		assert.Nil(t, env.artifact.LastHistoryUpdate)
	})

	t.Run("saves every day in one call", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		begin := testDay
		end := begin.AddDate(0, 0, 4)

		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.expectVulns(newTestOpenVuln(uuid.New(), 1.0))
		env.expectLastHistoryUpdateSaved()

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, end)
		require.NoError(t, err)

		env.artifactRiskHistoryRepository.AssertNumberOfCalls(t, "UpdateRiskAggregations", 1)
		require.Len(t, env.saved, 5)
	})

	t.Run("returns the error of the starting state lookup without rebuilding anything", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		snapshotErr := errors.New("snapshot lookup failed")

		env.artifactRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, snapshotErr)

		err := env.service.RebuildArtifactRiskHistory(context.Background(), nil, env.artifact, env.artifact.AssetID, testDay, testDay.AddDate(0, 0, 2))
		assert.ErrorIs(t, err, snapshotErr)
		assert.Empty(t, env.saved)
		assert.Nil(t, env.artifact.LastHistoryUpdate)
	})
}

func TestUpdateArtifactRiskAggregation(t *testing.T) {
	t.Run("rebuilds every day of the requested window", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		end := time.Now().UTC()
		begin := end.AddDate(0, 0, -3)

		vuln := newTestOpenVuln(uuid.New(), 1.0)
		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.expectVulns(vuln)
		env.expectLastHistoryUpdateSaved()

		err := env.service.UpdateArtifactRiskAggregation(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, end)
		assert.NoError(t, err)

		require.Len(t, env.saved, 4)
		for i, row := range env.saved {
			assert.Equal(t, endOfDay(begin.AddDate(0, 0, i)), row.Day)
		}
		// the vuln is new on the first day and unchanged afterwards
		assert.ElementsMatch(t, []string{vuln.ID.String()}, env.saved[0].DiffAddedDependencyVulns)
		for _, row := range env.saved[1:] {
			assert.Empty(t, row.DiffAddedDependencyVulns)
			assert.Empty(t, row.DiffRemovedDependencyVulns)
		}
		require.NotNil(t, env.artifact.LastHistoryUpdate)
		assert.Equal(t, endOfDay(end), *env.artifact.LastHistoryUpdate)
	})

	t.Run("does not go back further than one year", func(t *testing.T) {
		env := newRebuildTestEnv(t)

		oneYearAgo := time.Now().AddDate(-1, 0, 0)
		// the window ends the day after the one year limit, so only two days are left once the start is limited
		end := endOfDay(oneYearAgo).AddDate(0, 0, 1)

		env.artifactRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
		env.artifactRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, time.Time{}, mock.Anything).Return([]models.ArtifactRiskHistory{}, nil)
		env.expectVulns()
		env.expectLastHistoryUpdateSaved()

		err := env.service.UpdateArtifactRiskAggregation(context.Background(), nil, env.artifact, env.artifact.AssetID, time.Now().AddDate(-3, 0, 0), end)
		assert.NoError(t, err)

		require.Len(t, env.saved, 2)
		assert.Equal(t, endOfDay(oneYearAgo), env.saved[0].Day)
		assert.Equal(t, end, env.saved[1].Day)
	})

	t.Run("a window containing a snapshot day stores the full distribution on that day only", func(t *testing.T) {
		env := newRebuildTestEnv(t)
		snapshotDay := lastSnapshotDayUntil(env.service, time.Now().UTC())
		begin := snapshotDay.AddDate(0, 0, -1)

		low, critical := uuid.New(), uuid.New()
		env.expectStartState(endOfDay(begin).AddDate(0, 0, -1), nil, nil)
		env.expectVulns(newTestOpenVuln(low, 1.0), newTestOpenVuln(critical, 9.5))
		env.expectLastHistoryUpdateSaved()

		err := env.service.UpdateArtifactRiskAggregation(context.Background(), nil, env.artifact, env.artifact.AssetID, begin, snapshotDay)
		assert.NoError(t, err)

		require.Len(t, env.saved, 2)
		for name, column := range snapshotColumnsOf(env.saved[0].Distribution) {
			assert.Nil(t, column, name)
		}
		assert.ElementsMatch(t, []string{low.String()}, env.saved[1].Low)
		assert.ElementsMatch(t, []string{critical.String()}, env.saved[1].Critical)
	})
}

// rebuildTestEnv wires the statistics service to mocks for the rebuild of a risk history.
// It records every row that gets saved and plays back the vuln states of the rebuilt days.
type rebuildTestEnv struct {
	t        *testing.T
	service  *statisticsService
	artifact *models.Artifact

	statisticsRepository          *mocks.StatisticsRepository
	artifactRiskHistoryRepository *mocks.ArtifactRiskHistoryRepository
	assetVersionRepository        *mocks.AssetVersionRepository

	saved   []models.ArtifactRiskHistory
	saveErr error
}

func newRebuildTestEnv(t *testing.T) *rebuildTestEnv {
	t.Helper()

	env := &rebuildTestEnv{
		t:                             t,
		artifact:                      &models.Artifact{ArtifactName: "TestArtifact", AssetVersionName: "Test", AssetID: uuid.New()},
		statisticsRepository:          mocks.NewStatisticsRepository(t),
		artifactRiskHistoryRepository: mocks.NewArtifactRiskHistoryRepository(t),
		assetVersionRepository:        mocks.NewAssetVersionRepository(t),
	}
	env.service = NewStatisticsService(env.statisticsRepository, env.artifactRiskHistoryRepository, mocks.NewDependencyVulnRepository(t), env.assetVersionRepository)

	env.artifactRiskHistoryRepository.EXPECT().UpdateRiskAggregations(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ shared.DB, rows []models.ArtifactRiskHistory) error {
			if env.saveErr != nil {
				return env.saveErr
			}
			env.saved = append(env.saved, rows...)
			return nil
		}).Maybe()

	return env
}

// expectStartState mocks what openVulnIDsAt loads for the day before the rebuilt window:
// the latest snapshot (or none) and the diffs stored since then
func (env *rebuildTestEnv) expectStartState(at time.Time, snapshot *models.ArtifactRiskHistory, diffsSinceSnapshot []models.ArtifactRiskHistory) {
	from := time.Time{}
	if snapshot != nil {
		from = snapshot.Day
	}

	env.artifactRiskHistoryRepository.On("GetLatestSnapshotBefore", mock.Anything, mock.Anything, &env.artifact.ArtifactName, env.artifact.AssetVersionName, env.artifact.AssetID, at).Return(snapshot, nil)
	env.artifactRiskHistoryRepository.On("GetRiskHistory", mock.Anything, mock.Anything, &env.artifact.ArtifactName, env.artifact.AssetVersionName, env.artifact.AssetID, from, at).Return(diffsSinceSnapshot, nil)
}

// expectVulns answers the lookup of the artifact's vulns with their complete event history, the rebuild derives the state of every day from it
func (env *rebuildTestEnv) expectVulns(vulns ...models.DependencyVuln) {
	env.statisticsRepository.EXPECT().GetDependencyVulnsWithEvents(mock.Anything, mock.Anything, env.artifact.ArtifactName, env.artifact.AssetVersionName, env.artifact.AssetID).
		Return(vulns, nil)
}

// the last step of a rebuild stores the artifact through gorm directly, in a dry run the statement is only built and not executed
func (env *rebuildTestEnv) expectLastHistoryUpdateSaved() {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DryRun: true})
	require.NoError(env.t, err)

	env.assetVersionRepository.EXPECT().GetDB(mock.Anything, mock.Anything).Return(db)
}

var longBeforeTestDay = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

func newTestEvent(eventType dtos.VulnEventType, at time.Time) models.VulnEvent {
	return models.VulnEvent{Type: eventType, CreatedAt: at}
}

func newTestTimelineVuln(id uuid.UUID, risk float64, createdAt time.Time, events ...models.VulnEvent) models.DependencyVuln {
	vuln := newTestDependencyVuln(id, risk)
	vuln.CreatedAt = createdAt
	vuln.Events = events
	return vuln
}

func newTestOpenVuln(id uuid.UUID, risk float64) models.DependencyVuln {
	return newTestTimelineVuln(id, risk, longBeforeTestDay, newTestEvent(dtos.EventTypeDetected, longBeforeTestDay))
}

func newTestFixedVuln(id uuid.UUID, risk float64) models.DependencyVuln {
	return newTestTimelineVuln(id, risk, longBeforeTestDay,
		newTestEvent(dtos.EventTypeDetected, longBeforeTestDay),
		newTestEvent(dtos.EventTypeFixed, longBeforeTestDay.Add(time.Hour)),
	)
}

// the rebuild works on the last second of each day
func endOfDay(day time.Time) time.Time {
	day = day.UTC()
	return time.Date(day.Year(), day.Month(), day.Day(), 23, 59, 59, 0, time.UTC)
}

// firstSnapshotDayFrom returns the first day at or after the given one that is a snapshot day
func firstSnapshotDayFrom(statisticsService *statisticsService, from time.Time) time.Time {
	day := time.Date(from.UTC().Year(), from.UTC().Month(), from.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for !statisticsService.isSnapShotDay(day) {
		day = day.AddDate(0, 0, 1)
	}
	return day
}

// lastSnapshotDayUntil returns the last day at or before the given one that is a snapshot day
func lastSnapshotDayUntil(statisticsService *statisticsService, until time.Time) time.Time {
	day := time.Date(until.UTC().Year(), until.UTC().Month(), until.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for !statisticsService.isSnapShotDay(day) {
		day = day.AddDate(0, 0, -1)
	}
	return day
}

// snapshotColumnsOf returns the columns that mark a row as a snapshot: everything of the distribution except the diffs
func snapshotColumnsOf(distribution models.Distribution) map[string]pq.StringArray {
	columns := map[string]pq.StringArray{}

	value := reflect.ValueOf(distribution)
	for i := 0; i < value.NumField(); i++ {
		name := value.Type().Field(i).Name
		if strings.HasPrefix(name, "Diff") {
			continue
		}
		if column, ok := value.Field(i).Interface().(pq.StringArray); ok {
			columns[name] = column
		}
	}

	return columns
}
