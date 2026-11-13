package repositories

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// The risk history is computed on read from the open rows of public.vuln_state_intervals (one row per period a dependency vuln stayed in one state).
// The queries below only return the changes per day: a period adds +1 on the day it starts and -1 on the day it ends.
// sumUpChanges adds them up day by day, so every history row is the state at the end of its UTC day.
type artifactRiskHistoryRepository struct {
	db *gorm.DB
}

func NewArtifactRiskHistoryRepository(db *gorm.DB) *artifactRiskHistoryRepository {
	return &artifactRiskHistoryRepository{
		db: db,
	}
}

var _ shared.ArtifactRiskHistoryRepository = (*artifactRiskHistoryRepository)(nil)

func (r *artifactRiskHistoryRepository) getDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

// Every change query starts with a CTE scoped: the open periods counted for a series (column series_id) -
// the asset version, or the organization for the org history.
// In the artifact scopes a period only counts while the vuln was found in the artifact. The scan writes
// a link event only when the link actually changed, so detectedInArtifact and fixedInArtifact alternate.
const linkedScopedSQL = `
links AS MATERIALIZED (
	SELECT series_id, dependency_vuln_id, valid_from, valid_to
	FROM (
		SELECT la.series_id, e.dependency_vuln_id, e.type, e.created_at AS valid_from,
			coalesce(lead(e.created_at) OVER (PARTITION BY e.artifact_id, e.dependency_vuln_id ORDER BY e.created_at, e.id), 'infinity') AS valid_to
		FROM link_artifacts la
		JOIN public.vuln_events e ON e.artifact_id = la.artifact_id
		WHERE e.type IN ('detectedInArtifact', 'fixedInArtifact')
	) link_events
	WHERE type = 'detectedInArtifact'
), scoped AS MATERIALIZED (
	SELECT l.series_id, i.dependency_vuln_id,
		greatest(i.valid_from, l.valid_from) AS valid_from,
		nullif(least(coalesce(i.valid_to, 'infinity'), l.valid_to), 'infinity') AS valid_to,
		i.cve_purl_hash, i.risk, i.cvss, i.fixable
	FROM links l
	JOIN public.vuln_state_intervals i ON i.dependency_vuln_id = l.dependency_vuln_id
	WHERE i.state = 'open' AND i.valid_from < l.valid_to AND coalesce(i.valid_to, 'infinity') > l.valid_from
)`

// changesSQL continues after the CTE scoped and returns the changes per series, day, kind and severity bucket.
// The kinds: vuln = open vulns, firstSeen = the first day a vuln exists in the series (existing - open = fixed),
// cvePurl / cvePurlFixable = unique cve + purl pairs over all / only fixable vulns.
// The buckets: 0 low (< 4), 1 medium (< 7), 2 high (< 9), 3 critical; a cve without a known cvss is stored with -1 and has no bucket.
const changesSQL = `,
cve_purl_periods AS (
	-- a cve + purl pair counts once even if several vulns share it, so overlapping periods of a pair are merged (gaps and islands)
	SELECT *, CASE WHEN valid_from <= max(valid_to) OVER (PARTITION BY series_id, kind, cve_purl_hash ORDER BY valid_from, valid_to ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING)
		THEN 0 ELSE 1 END AS new_island
	FROM (
		SELECT series_id, cve_purl_hash, 'cvePurl' AS kind, valid_from, coalesce(valid_to, 'infinity') AS valid_to, risk, cvss FROM scoped
		UNION ALL
		SELECT series_id, cve_purl_hash, 'cvePurlFixable', valid_from, coalesce(valid_to, 'infinity'), risk, cvss FROM scoped WHERE fixable
	) pair_periods
), cve_purl_islands AS (
	SELECT series_id, kind, max(risk) AS risk, max(cvss) AS cvss, min(valid_from) AS valid_from, max(valid_to) AS valid_to
	FROM (
		SELECT *, sum(new_island) OVER (PARTITION BY series_id, kind, cve_purl_hash ORDER BY valid_from, valid_to ROWS UNBOUNDED PRECEDING) AS island
		FROM cve_purl_periods
	) numbered
	GROUP BY series_id, kind, cve_purl_hash, island
), changes AS (
	-- every change before the start day is folded into the start day, so adding up from the start day is complete
	SELECT series_id, greatest((valid_from AT TIME ZONE 'UTC')::date, CAST(@start AS date)) AS day, 'vuln' AS kind, 1 AS delta, risk, cvss, fixable FROM scoped
	UNION ALL
	SELECT series_id, greatest((valid_to AT TIME ZONE 'UTC')::date, CAST(@start AS date)), 'vuln', -1, risk, cvss, fixable FROM scoped WHERE valid_to IS NOT NULL
	UNION ALL
	SELECT series_id, greatest((min(valid_from) AT TIME ZONE 'UTC')::date, CAST(@start AS date)), 'firstSeen', 1, max(risk), max(cvss), false
	FROM scoped GROUP BY series_id, dependency_vuln_id
	UNION ALL
	SELECT series_id, greatest((valid_from AT TIME ZONE 'UTC')::date, CAST(@start AS date)), kind, 1, risk, cvss, false FROM cve_purl_islands
	UNION ALL
	SELECT series_id, greatest((valid_to AT TIME ZONE 'UTC')::date, CAST(@start AS date)), kind, -1, risk, cvss, false FROM cve_purl_islands WHERE valid_to <> 'infinity'
)
SELECT series_id, day, kind, fixable,
	CASE WHEN risk < 0 THEN NULL WHEN risk < 4 THEN 0 WHEN risk < 7 THEN 1 WHEN risk < 9 THEN 2 ELSE 3 END AS risk_bucket,
	CASE WHEN cvss < 0 THEN NULL WHEN cvss < 4 THEN 0 WHEN cvss < 7 THEN 1 WHEN cvss < 9 THEN 2 ELSE 3 END AS cvss_bucket,
	sum(delta) AS delta, sum(delta * risk) AS risk_delta
FROM changes
WHERE day <= CAST(@end AS date)
GROUP BY series_id, day, kind, fixable, risk_bucket, cvss_bucket
ORDER BY series_id, day`

// the given artifacts, one series per asset version - the artifacts have to belong to different asset versions
const artifactsChangesSQL = `WITH link_artifacts AS MATERIALIZED (
	SELECT asset_version_id AS series_id, id AS artifact_id FROM public.artifacts WHERE id = ANY(@artifactIDs)
),` + linkedScopedSQL + changesSQL

// every vuln of an asset version
const assetVersionChangesSQL = `WITH scoped AS MATERIALIZED (
	SELECT i.asset_version_id AS series_id, i.dependency_vuln_id, i.valid_from, i.valid_to, i.cve_purl_hash, i.risk, i.cvss, i.fixable
	FROM public.vuln_state_intervals i
	WHERE i.asset_version_id = @assetVersionID AND i.state = 'open'
)` + changesSQL

// every vuln of every asset version of an asset, one series per asset version
const assetChangesSQL = `WITH scoped AS MATERIALIZED (
	SELECT i.asset_version_id AS series_id, i.dependency_vuln_id, i.valid_from, i.valid_to, i.cve_purl_hash, i.risk, i.cvss, i.fixable
	FROM public.vuln_state_intervals i
	WHERE i.asset_version_id IN (SELECT id FROM public.asset_versions WHERE asset_id = @assetID) AND i.state = 'open'
)` + changesSQL

// every vuln of every asset version in an organization as a single series
const orgChangesSQL = `WITH scoped AS MATERIALIZED (
	SELECT CAST(@orgID AS uuid) AS series_id, i.dependency_vuln_id, i.valid_from, i.valid_to, i.cve_purl_hash, i.risk, i.cvss, i.fixable
	FROM public.vuln_state_intervals i
	WHERE i.asset_version_id IN (
		SELECT av.id
		FROM public.asset_versions av
		JOIN public.assets a ON a.id = av.asset_id
		JOIN public.projects p ON p.id = a.project_id
		WHERE p.organization_id = @orgID
	) AND i.state = 'open'
)` + changesSQL

// riskHistoryChange is a row of the change queries
type riskHistoryChange struct {
	SeriesID   uuid.UUID
	Day        time.Time
	Kind       string
	Fixable    bool
	RiskBucket *int
	CvssBucket *int
	Delta      int
	RiskDelta  float64
}

// loadChanges runs a change query and returns its changes per series, ordered by day
func (r *artifactRiskHistoryRepository) loadChanges(ctx context.Context, tx *gorm.DB, query string, args map[string]any, start, end time.Time) (map[uuid.UUID][]riskHistoryChange, error) {
	args["start"] = start.Format(time.DateOnly)
	args["end"] = end.Format(time.DateOnly)

	var changes []riskHistoryChange
	if err := r.getDB(ctx, tx).Raw(query, args).Scan(&changes).Error; err != nil {
		return nil, err
	}

	bySeries := make(map[uuid.UUID][]riskHistoryChange)
	for _, change := range changes {
		bySeries[change.SeriesID] = append(bySeries[change.SeriesID], change)
	}
	return bySeries, nil
}

// sumUpChanges adds up the changes of a series day by day from start to end
func sumUpChanges(changes []riskHistoryChange, start, end time.Time) []models.History {
	var open, existing int
	var openRisk, existingRisk float64
	distribution := models.Distribution{}

	history := []models.History{}
	next := 0
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		for ; next < len(changes) && !changes[next].Day.After(day); next++ {
			change := changes[next]
			switch change.Kind {
			case "vuln":
				open += change.Delta
				openRisk += change.RiskDelta
				addToSeverity(change.RiskBucket, change.Delta, &distribution.Low, &distribution.Medium, &distribution.High, &distribution.Critical)
				addToSeverity(change.CvssBucket, change.Delta, &distribution.LowCVSS, &distribution.MediumCVSS, &distribution.HighCVSS, &distribution.CriticalCVSS)
				if change.Fixable {
					addToSeverity(change.RiskBucket, change.Delta, &distribution.FixableLow, &distribution.FixableMedium, &distribution.FixableHigh, &distribution.FixableCritical)
					addToSeverity(change.CvssBucket, change.Delta, &distribution.FixableLowCVSS, &distribution.FixableMediumCVSS, &distribution.FixableHighCVSS, &distribution.FixableCriticalCVSS)
				}
			case "firstSeen":
				existing += change.Delta
				existingRisk += change.RiskDelta
			case "cvePurl":
				addToSeverity(change.RiskBucket, change.Delta, &distribution.CVEPurlLow, &distribution.CVEPurlMedium, &distribution.CVEPurlHigh, &distribution.CVEPurlCritical)
				addToSeverity(change.CvssBucket, change.Delta, &distribution.CVEPurlLowCVSS, &distribution.CVEPurlMediumCVSS, &distribution.CVEPurlHighCVSS, &distribution.CVEPurlCriticalCVSS)
			case "cvePurlFixable":
				addToSeverity(change.RiskBucket, change.Delta, &distribution.CVEPurlFixableLow, &distribution.CVEPurlFixableMedium, &distribution.CVEPurlFixableHigh, &distribution.CVEPurlFixableCritical)
				addToSeverity(change.CvssBucket, change.Delta, &distribution.CVEPurlFixableLowCVSS, &distribution.CVEPurlFixableMediumCVSS, &distribution.CVEPurlFixableHighCVSS, &distribution.CVEPurlFixableCriticalCVSS)
			}
		}

		closed := existing - open
		closedRisk := existingRisk - openRisk
		history = append(history, models.History{
			Distribution:         distribution,
			Day:                  day,
			OpenDependencyVulns:  open,
			FixedDependencyVulns: closed,
			SumOpenRisk:          roundRisk(openRisk),
			AvgOpenRisk:          averageRisk(openRisk, open),
			SumClosedRisk:        roundRisk(closedRisk),
			AvgClosedRisk:        averageRisk(closedRisk, closed),
		})
	}
	return history
}

// addToSeverity adds delta to the counter of the severity bucket, see changesSQL
func addToSeverity(bucket *int, delta int, low, medium, high, critical *int) {
	if bucket == nil {
		return
	}
	switch *bucket {
	case 0:
		*low += delta
	case 1:
		*medium += delta
	case 2:
		*high += delta
	case 3:
		*critical += delta
	}
}

// the risk sums are floats in which closed periods do not cancel out exactly
func roundRisk(risk float64) float64 {
	rounded := math.Round(risk*10000) / 10000
	if rounded == 0 {
		// a sum which cancelled out to a tiny negative remainder would be rounded to -0
		return 0
	}
	return rounded
}

func averageRisk(sum float64, count int) float64 {
	if count == 0 {
		return 0
	}
	return roundRisk(sum / float64(count))
}

// the controllers parse the requested days as UTC midnight
func utcDay(t time.Time) time.Time {
	year, month, day := t.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// withHistory returns one row per history day, all carrying the names of the series
func withHistory(names models.ArtifactRiskHistory, history []models.History) []models.ArtifactRiskHistory {
	rows := make([]models.ArtifactRiskHistory, 0, len(history))
	for _, day := range history {
		names.History = day
		rows = append(rows, names)
	}
	return rows
}

func (r *artifactRiskHistoryRepository) GetRiskHistory(ctx context.Context, tx *gorm.DB, artifactID *uuid.UUID, assetVersionID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	start, end = utcDay(start), utcDay(end)

	if artifactID != nil {
		var artifacts []models.ArtifactRiskHistory
		err := r.getDB(ctx, tx).Raw(`SELECT a.id AS artifact_id, a.asset_id, a.artifact_name, av.name AS asset_version_name
			FROM public.artifacts a
			JOIN public.asset_versions av ON av.id = a.asset_version_id
			WHERE a.id = ? AND a.asset_version_id = ?`, *artifactID, assetVersionID).Scan(&artifacts).Error
		if err != nil || len(artifacts) == 0 {
			return []models.ArtifactRiskHistory{}, err
		}

		changes, err := r.loadChanges(ctx, tx, artifactsChangesSQL, map[string]any{"artifactIDs": pq.Array([]uuid.UUID{*artifactID})}, start, end)
		if err != nil {
			return nil, err
		}
		return withHistory(artifacts[0], sumUpChanges(changes[assetVersionID], start, end)), nil
	}

	var assetVersions []models.ArtifactRiskHistory
	err := r.getDB(ctx, tx).Raw(`SELECT asset_id, name AS asset_version_name FROM public.asset_versions WHERE id = ?`, assetVersionID).Scan(&assetVersions).Error
	if err != nil || len(assetVersions) == 0 {
		return []models.ArtifactRiskHistory{}, err
	}

	changes, err := r.loadChanges(ctx, tx, assetVersionChangesSQL, map[string]any{"assetVersionID": assetVersionID}, start, end)
	if err != nil {
		return nil, err
	}
	return withHistory(assetVersions[0], sumUpChanges(changes[assetVersionID], start, end)), nil
}

func (r *artifactRiskHistoryRepository) GetRiskHistoryWithVersion(ctx context.Context, tx *gorm.DB, artifactName *string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistoryWithVersion, error) {
	start, end = utcDay(start), utcDay(end)

	type assetVersion struct {
		AssetVersionID uuid.UUID
		models.ArtifactRiskHistoryWithVersion
	}
	var assetVersions []assetVersion
	var changes map[uuid.UUID][]riskHistoryChange
	var err error
	if artifactName != nil {
		// across asset versions the artifact is only identified by its name
		err = r.getDB(ctx, tx).Raw(`SELECT av.id AS asset_version_id, av.asset_id, av.name AS asset_version_name, av.slug, av.default_branch, av.type,
				a.id AS artifact_id, a.artifact_name
			FROM public.asset_versions av
			JOIN public.artifacts a ON a.asset_version_id = av.id AND a.artifact_name = ?
			WHERE av.asset_id = ?
			ORDER BY av.name`, *artifactName, assetID).Scan(&assetVersions).Error
		if err != nil {
			return nil, err
		}
		artifactIDs := make([]uuid.UUID, 0, len(assetVersions))
		for _, version := range assetVersions {
			artifactIDs = append(artifactIDs, version.ArtifactID)
		}
		changes, err = r.loadChanges(ctx, tx, artifactsChangesSQL, map[string]any{"artifactIDs": pq.Array(artifactIDs)}, start, end)
	} else {
		err = r.getDB(ctx, tx).Raw(`SELECT av.id AS asset_version_id, av.asset_id, av.name AS asset_version_name, av.slug, av.default_branch, av.type
			FROM public.asset_versions av
			WHERE av.asset_id = ?
			ORDER BY av.name`, assetID).Scan(&assetVersions).Error
		if err != nil {
			return nil, err
		}
		changes, err = r.loadChanges(ctx, tx, assetChangesSQL, map[string]any{"assetID": assetID}, start, end)
	}
	if err != nil {
		return nil, err
	}

	histories := make([][]models.History, len(assetVersions))
	for i, version := range assetVersions {
		histories[i] = sumUpChanges(changes[version.AssetVersionID], start, end)
	}

	// ordered by day, then by asset version name
	rows := []models.ArtifactRiskHistoryWithVersion{}
	for day := 0; len(histories) > 0 && day < len(histories[0]); day++ {
		for i, version := range assetVersions {
			row := version.ArtifactRiskHistoryWithVersion
			row.History = histories[i][day]
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (r *artifactRiskHistoryRepository) GetLatestRiskHistory(ctx context.Context, tx *gorm.DB, artifactID *uuid.UUID, assetVersionID uuid.UUID) (*models.ArtifactRiskHistory, error) {
	today := time.Now().UTC()
	history, err := r.GetRiskHistory(ctx, tx, artifactID, assetVersionID, today, today)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, nil
	}
	return &history[0], nil
}

func (r *artifactRiskHistoryRepository) GetRiskHistoryForOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, start, end time.Time) ([]dtos.OrgRiskHistory, error) {
	start, end = utcDay(start), utcDay(end)

	changes, err := r.loadChanges(ctx, tx, orgChangesSQL, map[string]any{"orgID": orgID}, start, end)
	if err != nil {
		return nil, err
	}

	history := []dtos.OrgRiskHistory{}
	for _, day := range sumUpChanges(changes[orgID], start, end) {
		history = append(history, dtos.OrgRiskHistory{Day: day.Day, Distribution: dtos.Distribution(day.Distribution)})
	}
	return history, nil
}

// derives the state periods of the dependency vulns of an asset from their state events, fixed periods are not stored.
// reopened opens, detected opens unless the vuln was accepted or marked as false positive before, every other state event sets its own state.
const vulnStateIntervalsSQL = `
INSERT INTO public.vuln_state_intervals (dependency_vuln_id, asset_version_id, state, valid_from, valid_to, cve_purl_hash, risk, cvss, fixable)
WITH vulns AS MATERIALIZED (
	SELECT dv.id, dv.asset_signature, dv.asset_version_id, dv.cve_id, dv.component_purl, dv.risk_assessment, dv.direct_dependency_fixed_version
	FROM public.dependency_vulns dv
	WHERE dv.asset_id = @assetID
), events AS (
	SELECT e.dependency_vuln_id, e.created_at, e.id, e.type
	FROM vulns v
	JOIN public.vuln_events e ON e.dependency_vuln_id = v.id
	WHERE e.type = ANY(@stateEventTypes)
	UNION ALL
	-- group events apply to every vuln with the same asset signature
	SELECT v.id, e.created_at, e.id, e.type
	FROM vulns v
	JOIN public.vuln_events e ON e.asset_signature = v.asset_signature
	WHERE e.dependency_vuln_id IS NULL AND e.type = ANY(@stateEventTypes)
), grouped AS (
	-- every detected event belongs to the decision of the last non-detected event before it
	SELECT *, count(*) FILTER (WHERE type <> 'detected')
		OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS decision_group
	FROM events
), states AS (
	SELECT dependency_vuln_id, created_at, id,
		CASE
			WHEN type = 'reopened' THEN 'open'
			WHEN type <> 'detected' THEN type
			WHEN decision IN ('falsePositive', 'accepted') THEN decision
			ELSE 'open'
		END AS state
	FROM (
		SELECT *, first_value(type) OVER (PARTITION BY dependency_vuln_id, decision_group ORDER BY created_at, id) AS decision
		FROM grouped
	) decided
), changes AS (
	SELECT *, lag(state) OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS prev_state
	FROM states
), boundaries AS (
	SELECT dependency_vuln_id, created_at, state,
		lead(created_at) OVER (PARTITION BY dependency_vuln_id ORDER BY created_at, id) AS next_change
	FROM changes
	WHERE prev_state IS NULL OR state <> prev_state
)
SELECT b.dependency_vuln_id, v.asset_version_id, b.state, b.created_at, b.next_change,
	hashtextextended(v.cve_id || '|' || v.component_purl, 0),
	coalesce(v.risk_assessment, 0), coalesce(c.cvss, 0),
	coalesce(v.direct_dependency_fixed_version, '') <> ''
FROM boundaries b
JOIN vulns v ON v.id = b.dependency_vuln_id
LEFT JOIN public.cves c ON c.cve = v.cve_id
WHERE b.state <> 'fixed'`

var stateEventTypes = pq.StringArray{
	string(dtos.EventTypeDetected),
	string(dtos.EventTypeReopened),
	string(dtos.EventTypeFixed),
	string(dtos.EventTypeFalsePositive),
	string(dtos.EventTypeAccepted),
	string(dtos.EventTypeMarkedForTransfer),
}

func (r *artifactRiskHistoryRepository) RecalculateForAsset(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) error {
	return r.getDB(ctx, tx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`DELETE FROM public.vuln_state_intervals
			WHERE dependency_vuln_id IN (SELECT id FROM public.dependency_vulns WHERE asset_id = ?)`, assetID).Error; err != nil {
			return err
		}
		return tx.Exec(vulnStateIntervalsSQL, map[string]any{"assetID": assetID, "stateEventTypes": stateEventTypes}).Error
	})
}
