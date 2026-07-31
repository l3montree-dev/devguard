package crowdsourcevexing

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test constants and helpers ---

const (
	testAssessmentPrimary   = string(dtos.ComponentNotPresent)
	testAssessmentSecondary = string(dtos.VulnerableCodeNotPresent)
)

// uid deterministically derives a uuid.UUID from a human-readable test ID, so
// tests can keep using readable strings like "org-0" while the production
// code works with uuid.UUID.
func uid(s string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(s))
}

func oldOrg() time.Time {
	return time.Now().Add(-365 * 24 * time.Hour)
}

func youngOrg() time.Time {
	return time.Now().Add(-7 * 24 * time.Hour)
}

func makeOrg(id string, trustscore float64, createdAt time.Time) Organization {
	return Organization{
		ID:         uid(id),
		Trustscore: trustscore,
		CreatedAt:  createdAt,
		CreatedBy:  "user1",
		UserIDs:    []string{"user1"},
	}
}

func makeOrgWithCreator(id string, trustscore float64, createdAt time.Time, creator string) Organization {
	return Organization{
		ID:         uid(id),
		Trustscore: trustscore,
		CreatedAt:  createdAt,
		CreatedBy:  creator,
		UserIDs:    []string{creator},
	}
}

func makeProject(id, orgID string, trustscore float64) Project {
	return Project{ID: uid(id), OrganizationID: uid(orgID), Trustscore: trustscore}
}

func makeAsset(id, projectID string) models.Asset {
	return models.Asset{Model: models.Model{ID: uid(id)}, ProjectID: uid(projectID)}
}

// makeVexRule creates a models.VEXRule for the given candidate ID (rules sharing the
// same ID are treated as votes for the same recommendation).
func makeVexRule(id, assetID, assessment string) models.VEXRule {
	return models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{
			ID:                      id,
			CELExpression:           fmt.Sprintf("vuln.cveId == %q", id),
			MechanicalJustification: dtos.MechanicalJustificationType(assessment),
			Justification:           "test reasoning",
		},
		AssetID: uid(assetID),
	}
}

// generateDistinctVoters creates n distinct org/project/asset chains plus
// matching VexRules for the given candidate ID and assessment.
// Each voter gets a unique creator to avoid diminishing-returns penalties.
func generateDistinctVoters(n int, id, assessment string, trustscore float64, createdAt time.Time) ([]models.VEXRule, []Organization, []Project, []models.Asset) {
	var rules []models.VEXRule
	var orgs []Organization
	var projects []Project
	var assets []models.Asset

	for i := range n {
		suffix := fmt.Sprintf("%d", i)
		orgID := "org-" + suffix
		projID := "proj-" + suffix
		assetID := "asset-" + suffix

		orgs = append(orgs, makeOrgWithCreator(orgID, trustscore, createdAt, "creator-"+suffix))
		projects = append(projects, makeProject(projID, orgID, trustscore))
		assets = append(assets, makeAsset(assetID, projID))
		rules = append(rules, makeVexRule(id, assetID, assessment))
	}
	return rules, orgs, projects, assets
}

// rekey derives fresh, related IDs (prefixed off the existing ones) so
// entities from two generateDistinctVoters calls don't collide.
func rekey(prefix string, rules []models.VEXRule, orgs []Organization, projects []Project, assets []models.Asset) {
	for i := range orgs {
		newOrgID := uid(prefix + orgs[i].ID.String())
		newProjID := uid(prefix + projects[i].ID.String())
		newAssetID := uid(prefix + assets[i].ID.String())

		orgs[i].ID = newOrgID
		orgs[i].CreatedBy = prefix + orgs[i].CreatedBy
		projects[i].OrganizationID = newOrgID
		projects[i].ID = newProjID
		assets[i].ProjectID = newProjID
		assets[i].ID = newAssetID
		rules[i].AssetID = newAssetID
	}
}

// merge concatenates slices from two voter sets.
func merge(
	r1, r2 []models.VEXRule, o1, o2 []Organization, p1, p2 []Project, a1, a2 []models.Asset,
) ([]models.VEXRule, []Organization, []Project, []models.Asset) {
	return append(r1, r2...), append(o1, o2...), append(p1, p2...), append(a1, a2...)
}

// Helper function tests

func TestFindVexRuleByID(t *testing.T) {
	rules := []models.VEXRule{
		makeVexRule("rule-1", "a1", testAssessmentPrimary),
		makeVexRule("rule-2", "a2", testAssessmentSecondary),
		makeVexRule("rule-3", "a3", testAssessmentSecondary),
	}

	identityMap := map[string]string{"rule-1": "rule-1", "rule-2": "rule-2", "rule-3": "rule-3"}

	found, ok := getVexRuleFromMatchingRules("rule-1", identityMap, rules)
	assert.True(t, ok)
	assert.Equal(t, uid("a1"), found.AssetID)
	assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentPrimary), found.MechanicalJustification)

	found, ok = getVexRuleFromMatchingRules("rule-3", identityMap, rules)
	assert.True(t, ok)
	assert.Equal(t, uid("a3"), found.AssetID)
	assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentSecondary), found.MechanicalJustification)

	_, ok = getVexRuleFromMatchingRules("nonexistent", identityMap, rules)
	assert.False(t, ok)
}

func TestUserVoteTracker(t *testing.T) {
	tracker := newUserVoteTracker()
	orgAlice := Organization{CreatedBy: "alice"}
	orgBob := Organization{CreatedBy: "bob"}

	assert.Equal(t, 1.0, tracker.recordVoteAndGetFactor(orgAlice, 0.1))
	assert.Equal(t, 0.1, tracker.recordVoteAndGetFactor(orgAlice, 0.1))
	assert.Equal(t, 1.0, tracker.recordVoteAndGetFactor(orgBob, 0.1))
	assert.Equal(t, 0.01, tracker.recordVoteAndGetFactor(orgAlice, 0.1))
}

// CrowdsourcedVexing

// This test covers that even in a uniform vote, the correct rule is recommended and no errors are thrown
func TestCrowdsourcedVexing_UniformVote(t *testing.T) {
	rules, orgs, projects, assets := generateDistinctVoters(5, "rule-uniform", testAssessmentPrimary, 0.8, oldOrg())
	result, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
	require.NoError(t, err)
	assert.Equal(t, "rule-uniform", result.ID)
	assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentPrimary), result.MechanicalJustification)
}

// Trust score behavior

// This test covers if higher trust score voters can outweigh lower trust score voters, when the number of votes is equal
func TestCrowdsourcedVexing_HigherTrustscoreWins(t *testing.T) {
	cases := []struct {
		name     string
		lowTrust float64
		hiTrust  float64
	}{
		{"0.3 vs 0.7", 0.3, 0.7},
		{"0.1 vs 0.5", 0.1, 0.5},
		{"0.5 vs 0.9", 0.5, 0.9},
		{"0.01 vs 0.99", 0.01, 0.99},
		{"0.5 vs 0.51", 0.5, 0.51},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lowR, lowO, lowP, lowA := generateDistinctVoters(4, "rule-low", testAssessmentSecondary, tc.lowTrust, oldOrg())
			hiR, hiO, hiP, hiA := generateDistinctVoters(4, "rule-high", testAssessmentPrimary, tc.hiTrust, oldOrg())
			rekey("hi-", hiR, hiO, hiP, hiA)
			allR, allO, allP, allA := merge(lowR, hiR, lowO, hiO, lowP, hiP, lowA, hiA)

			result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
			require.NoError(t, err)
			assert.Equal(t, "rule-high", result.ID, "higher trust score votes should win")
		})
	}
}

// This tests if the higher trust score between organization and project is used
// If the organization trust score is used, the malicious rule should win the vote
// This test assumes that TestCrowdsourcedVexing_HigherTrustscoreWins passed
func TestCrowdsourcedVexing_UsesMaxOfOrgAndProjectTrustscore(t *testing.T) {
	var rules []models.VEXRule
	var orgs []Organization
	var projects []Project
	var assets []models.Asset

	for range 5 {
		orgs = append(orgs, makeOrgWithCreator("org-mal", 0.3, oldOrg(), "creator-mal"))
		projects = append(projects, makeProject("proj-mal", "org-mal", 0.3))
		assets = append(assets, makeAsset("asset-mal", "proj-mal"))
		rules = append(rules, makeVexRule("rule-mal", "asset-mal", testAssessmentSecondary))
	}

	for i := range 5 {
		s := fmt.Sprintf("%d", i)
		orgs = append(orgs, makeOrgWithCreator("org-"+s, 0.1, oldOrg(), "creator-"+s))
		projects = append(projects, makeProject("proj-"+s, "org-"+s, 0.9))
		assets = append(assets, makeAsset("asset-"+s, "proj-"+s))
		rules = append(rules, makeVexRule("rule-good", "asset-"+s, testAssessmentPrimary))
	}

	result, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
	require.NoError(t, err)
	assert.Equal(t, "rule-good", result.ID, "the higher project trust score should be used over the organization trust score")
}

func TestCrowdsourcedVexing_ProjectsOnly(t *testing.T) {
	var rules []models.VEXRule
	var orgs []Organization
	var projects []Project
	var assets []models.Asset

	var mRules []models.VEXRule
	var mOrgs []Organization
	var mProjects []Project
	var mAssets []models.Asset

	for i := range 5 {
		s := fmt.Sprintf("%d", i)
		mOrgs = append(mOrgs, makeOrgWithCreator("m-org-"+s, 0, oldOrg(), "creator-"+s))
		mProjects = append(mProjects, makeProject("m-proj-"+s, "m-org-"+s, 0.2))
		mAssets = append(mAssets, makeAsset("m-asset-"+s, "m-proj-"+s))
		mRules = append(mRules, makeVexRule("rule-mal", "m-asset-"+s, testAssessmentPrimary))
	}

	for i := range 5 {
		s := fmt.Sprintf("%d", i)
		orgs = append(orgs, makeOrgWithCreator("org-"+s, 0, oldOrg(), "creator-"+s))
		projects = append(projects, makeProject("proj-"+s, "org-"+s, 0.9))
		assets = append(assets, makeAsset("asset-"+s, "proj-"+s))
		rules = append(rules, makeVexRule("rule-good", "asset-"+s, testAssessmentSecondary))
	}

	allR, allO, allP, allA := merge(rules, mRules, orgs, mOrgs, projects, mProjects, assets, mAssets)

	result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
	require.NoError(t, err)
	assert.Equal(t, "rule-good", result.ID)
}

func TestCrowdsourcedVexing_QuantityVsQuality(t *testing.T) {
	t.Run("few high-trust voters beat many low-trust voters", func(t *testing.T) {
		// 4 voters at 0.9 = 3.6  vs  10 voters at 0.1 = 1.0
		hiR, hiO, hiP, hiA := generateDistinctVoters(4, "rule-high", testAssessmentPrimary, 0.9, oldOrg())
		loR, loO, loP, loA := generateDistinctVoters(10, "rule-low", testAssessmentSecondary, 0.1, oldOrg())
		rekey("lo-", loR, loO, loP, loA)
		allR, allO, allP, allA := merge(hiR, loR, hiO, loO, hiP, loP, hiA, loA)

		result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-high", result.ID, "quality should beat quantity")
	})

	t.Run("many moderate-trust voters beat few high-trust voters", func(t *testing.T) {
		// 4 voters at 0.5 = 2.0  vs  10 voters at 0.3 = 3.0
		fewR, fewO, fewP, fewA := generateDistinctVoters(4, "rule-few", testAssessmentPrimary, 0.5, oldOrg())
		manyR, manyO, manyP, manyA := generateDistinctVoters(10, "rule-many", testAssessmentSecondary, 0.3, oldOrg())
		rekey("many-", manyR, manyO, manyP, manyA)
		allR, allO, allP, allA := merge(fewR, manyR, fewO, manyO, fewP, manyP, fewA, manyA)

		result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-many", result.ID, "enough moderate-trust quantity can outweigh fewer high-trust voters")
	})
}

// ============================================================
// Security / Mitigation tests
// ============================================================

// [Mitigation 10,11] Organization must be older than minOrganizationAgeInDays.
func TestSecurity_MinOrganizationAge(t *testing.T) {
	t.Run("young organizations are rejected", func(t *testing.T) {
		oldR, oldO, oldP, oldA := generateDistinctVoters(4, "rule-old", testAssessmentPrimary, 0.1, oldOrg())
		yngR, yngO, yngP, yngA := generateDistinctVoters(4, "rule-young", testAssessmentSecondary, 0.8, youngOrg())
		rekey("yng-", yngR, yngO, yngP, yngA)
		allR, allO, allP, allA := merge(oldR, yngR, oldO, yngO, oldP, yngP, oldA, yngA)

		rule, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-old", rule.ID)
	})

	t.Run("boundary age is accepted", func(t *testing.T) {
		boundary := time.Now().Add(-time.Duration(minOrganizationAgeInDays)*24*time.Hour - time.Minute)
		oldR, oldO, oldP, oldA := generateDistinctVoters(3, "rule-old", testAssessmentPrimary, 0.1, oldOrg())
		yngR, yngO, yngP, yngA := generateDistinctVoters(3, "rule-young", testAssessmentSecondary, 0.8, boundary)
		rekey("yng-", yngR, yngO, yngP, yngA)
		allR, allO, allP, allA := merge(oldR, yngR, oldO, yngO, oldP, yngP, oldA, yngA)

		rule, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-young", rule.ID)
	})
}

// [Mitigation 15] Minimum voter threshold must be enforced.
func TestSecurity_MinVoterThreshold(t *testing.T) {
	t.Run("exactly threshold voters succeeds", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		result, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, "rule-a", result.ID)
	})

	t.Run("threshold minus one returns error", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold-1, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("zero voters returns error", func(t *testing.T) {
		_, _, _, err := CrowdsourcedVexing([]models.VEXRule{}, []Organization{}, []Project{}, []models.Asset{})
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})
}

// [Mitigation 20] Replay protection — duplicate votes from same org+project are ignored.
func TestSecurity_ReplayProtection(t *testing.T) {
	t.Run("duplicate org and project only counts once", func(t *testing.T) {
		org := makeOrg("replay-org", 0.9, oldOrg())
		project := makeProject("replay-proj", "replay-org", 0.9)
		asset := makeAsset("replay-asset", "replay-proj")

		var rules []models.VEXRule
		for range 5 {
			rules = append(rules, makeVexRule("rule-a", "replay-asset", testAssessmentPrimary))
		}

		result, _, _, err := CrowdsourcedVexing(rules, []Organization{org}, []Project{project}, []models.Asset{asset})
		require.NoError(t, err, "1 deduplicated vote should still meet the current minVoterThreshold")
		assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentPrimary), result.MechanicalJustification)

		// The important security property: replaying the same org+project 5x must not
		// out-vote a single distinct voter casting a conflicting assessment once.
		var singleVoterRules []models.VEXRule
		singleVoterRules = append(singleVoterRules, rules...)
		singleVoterRules = append(singleVoterRules, makeVexRule("rule-b", "replay-asset-2", testAssessmentSecondary))

		orgB := makeOrg("replay-org-2", 0.9, oldOrg())
		projectB := makeProject("replay-proj-2", "replay-org-2", 0.9)
		assetB := makeAsset("replay-asset-2", "replay-proj-2")

		result2, _, _, err := CrowdsourcedVexing(singleVoterRules, []Organization{org, orgB}, []Project{project, projectB}, []models.Asset{asset, assetB})
		require.NoError(t, err)
		assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentPrimary), result2.MechanicalJustification,
			"5 duplicate votes from same org+project should still only count as 1 vote, not outweigh a single distinct voter's conflicting vote")
	})

	t.Run("same org different projects count separately", func(t *testing.T) {
		org := makeOrg("shared-org", 0.8, oldOrg())

		var rules []models.VEXRule
		var projects []Project
		var assets []models.Asset
		for i := range 5 {
			s := fmt.Sprintf("%d", i)
			projID := "diff-proj-" + s
			assetID := "diff-asset-" + s
			projects = append(projects, makeProject(projID, "shared-org", 0.8))
			assets = append(assets, makeAsset(assetID, projID))
			rules = append(rules, makeVexRule("rule-a", assetID, testAssessmentPrimary))
		}

		result, _, _, err := CrowdsourcedVexing(rules, []Organization{org}, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentPrimary), result.MechanicalJustification)
	})
}

// [Mitigation 30] Input validation — only valid assessment values accepted.
func TestSecurity_AssessmentInputValidation(t *testing.T) {
	invalidAssessments := []string{
		"",
		"not-affected",
		"AFFECTED",
		"False-Positive",
		"malicious-payload",
		"<script>alert(1)</script>",
		"'; DROP TABLE vex_rules; --",
	}

	for _, bad := range invalidAssessments {
		t.Run("invalid assessment: "+bad, func(t *testing.T) {
			rules, orgs, projects, assets := generateDistinctVoters(5, "rule-bad", bad, 0.8, oldOrg())
			_, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
			assert.ErrorIs(t, err, ErrNoRecommendation, "assessment '%s' should not produce valid votes", bad)
		})
	}
}

// Negative trust scores should not produce a winning vote.
func TestSecurity_NegativeTrustscores(t *testing.T) {
	t.Run("negative trust", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, -1.0, oldOrg())
		_, _, _, err := CrowdsourcedVexing(rules, orgs, projects, assets)
		assert.Error(t, err)
	})
}

// [Mitigation 31] Tie-breaking — no recommendation is returned when scores are equal.
func TestSecurity_TieBreaking(t *testing.T) {
	t.Run("same rule different assessment tie - return nothing", func(t *testing.T) {
		affR, affO, affP, affA := generateDistinctVoters(4, "rule-a", testAssessmentSecondary, 0.5, oldOrg())
		fpR, fpO, fpP, fpA := generateDistinctVoters(4, "rule-b", testAssessmentPrimary, 0.5, oldOrg())
		rekey("fp-", fpR, fpO, fpP, fpA)
		allR, allO, allP, allA := merge(affR, fpR, affO, fpO, affP, fpP, affA, fpA)

		_, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		assert.ErrorIs(t, err, ErrNoRecommendation, "tie should return no models.VEXRule")
	})
}

// [Mitigation 8] Diminishing returns: same user creating many orgs gets less vote weight.
func TestSecurity_DiminishingReturns(t *testing.T) {

	t.Run("same creator multiple orgs diminished vs distinct creators", func(t *testing.T) {
		var sameRules []models.VEXRule
		var sameOrgs []Organization
		var sameProjs []Project
		var sameAssets []models.Asset
		for i := range 100 {
			s := fmt.Sprintf("%d", i)
			sameOrgs = append(sameOrgs, makeOrgWithCreator("deep-same-org-"+s, 0.3, oldOrg(), "deep-single-user"))
			sameProjs = append(sameProjs, makeProject("deep-same-proj-"+s, "deep-same-org-"+s, 0.3))
			sameAssets = append(sameAssets, makeAsset("deep-same-asset-"+s, "deep-same-proj-"+s))
			sameRules = append(sameRules, makeVexRule("rule-same", "deep-same-asset-"+s, testAssessmentPrimary))
		}

		distinctR, distinctO, distinctP, distinctA := generateDistinctVoters(1, "rule-distinct", testAssessmentSecondary, 0.9, oldOrg())
		rekey("dist-", distinctR, distinctO, distinctP, distinctA)

		allR, allO, allP, allA := merge(sameRules, distinctR, sameOrgs, distinctO, sameProjs, distinctP, sameAssets, distinctA)

		result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-distinct", result.ID,
			"distinct creators should outweigh a single creator with many orgs due to diminishing returns")
	})

	t.Run("creators on the same trustlevel can compete with each other using vote volume", func(t *testing.T) {
		distinct1R, distinct1O, distinct1P, distinct1A := generateDistinctVoters(4, "rule-1", testAssessmentPrimary, 0.8, oldOrg())
		distinct2R, distinct2O, distinct2P, distinct2A := generateDistinctVoters(5, "rule-2", testAssessmentSecondary, 0.8, oldOrg())
		rekey("dist-", distinct1R, distinct1O, distinct1P, distinct1A)

		allR, allO, allP, allA := merge(distinct2R, distinct1R, distinct2O, distinct1O, distinct2P, distinct1P, distinct2A, distinct1A)

		result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-2", result.ID,
			"20 same-creator votes (≈1.0) should not outweigh 4 distinct voters (2.0)")
	})
}

// ============================================================
// Edge cases
// ============================================================

func TestEdgeCase_MissingEntities(t *testing.T) {
	t.Run("missing assets", func(t *testing.T) {
		rules, orgs, projects, _ := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, _, _, err := CrowdsourcedVexing(rules, orgs, projects, []models.Asset{})
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("missing projects", func(t *testing.T) {
		rules, orgs, _, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, _, _, err := CrowdsourcedVexing(rules, orgs, []Project{}, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("missing organizations", func(t *testing.T) {
		rules, _, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, _, _, err := CrowdsourcedVexing(rules, []Organization{}, projects, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("no rules returns error", func(t *testing.T) {
		_, orgs, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, _, _, err := CrowdsourcedVexing([]models.VEXRule{}, orgs, projects, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})
}

// Very small trust scores should still work when enough voters agree.
// This is interesting since this means that the system is not 100% secure against mass-creation attacks
// Trust scores improve the resistance against such attacks, but do not extinguish them completely
// Now the question is, where is the threshold
// Referring back to byzantine generals problem and 50% threshold of etherium
// Application of diminishing returns show by math (exponential decay) that one low trusted user cannot out-vote a high-trusted user
func TestEdgeCase_VerySmallTrustscores(t *testing.T) {
	rules, orgs, projects, assets := generateDistinctVoters(100, "rule-many", testAssessmentSecondary, 0.01, oldOrg())
	tRules, tOrgs, tProjects, tAssets := generateDistinctVoters(1, "rule-single", testAssessmentPrimary, 0.99, oldOrg())
	rekey("t-", tRules, tOrgs, tProjects, tAssets)

	allR, allO, allP, allA := merge(rules, tRules, orgs, tOrgs, projects, tProjects, assets, tAssets)

	result, _, _, err := CrowdsourcedVexing(allR, allO, allP, allA)
	require.NoError(t, err)
	assert.Equal(t, dtos.MechanicalJustificationType(testAssessmentSecondary), result.MechanicalJustification, "even very small positive trust should produce a result")
}
