package crowdsourcevexing

import (
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test constants and helpers ---

const (
	testAssessmentPrimary   = string(dtos.ComponentNotPresent)
	testAssessmentSecondary = string(dtos.VulnerableCodeNotPresent)
)

func oldOrg() time.Time {
	return time.Now().Add(-365 * 24 * time.Hour)
}

func youngOrg() time.Time {
	return time.Now().Add(-7 * 24 * time.Hour)
}

func makeOrg(id string, trustscore float64, createdAt time.Time) Organization {
	return Organization{
		ID:         id,
		Trustscore: trustscore,
		CreatedAt:  createdAt,
		CreatedBy:  "user1",
		UserIDs:    []string{"user1"},
	}
}

func makeOrgWithCreator(id string, trustscore float64, createdAt time.Time, creator string) Organization {
	return Organization{
		ID:         id,
		Trustscore: trustscore,
		CreatedAt:  createdAt,
		CreatedBy:  creator,
		UserIDs:    []string{creator},
	}
}

func makeProject(id, orgID string, trustscore float64) Project {
	return Project{ID: id, OrganizationID: orgID, Trustscore: trustscore}
}

func makeAsset(id, projectID string) Asset {
	return Asset{ID: id, ProjectID: projectID}
}

// makeVexRule creates a VexRule for the given candidate ID (rules sharing the
// same ID are treated as votes for the same recommendation).
func makeVexRule(id, assetID, assessment string) VexRule {
	return VexRule{
		ID:            id,
		CELExpression: "cel-expr-" + id,
		AssetID:       assetID,
		Assessment:    assessment,
		Reasoning:     "test reasoning",
	}
}

// generateDistinctVoters creates n distinct org/project/asset chains plus
// matching VexRules for the given candidate ID and assessment.
// Each voter gets a unique creator to avoid diminishing-returns penalties.
func generateDistinctVoters(n int, id, assessment string, trustscore float64, createdAt time.Time) ([]VexRule, []Organization, []Project, []Asset) {
	var rules []VexRule
	var orgs []Organization
	var projects []Project
	var assets []Asset

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

// rekey adjusts IDs so entities from two generateDistinctVoters calls don't collide.
func rekey(prefix string, rules []VexRule, orgs []Organization, projects []Project, assets []Asset) {
	for i := range orgs {
		orgs[i].ID = prefix + orgs[i].ID
		orgs[i].CreatedBy = prefix + orgs[i].CreatedBy
		projects[i].OrganizationID = orgs[i].ID
		projects[i].ID = prefix + projects[i].ID
		assets[i].ProjectID = projects[i].ID
		assets[i].ID = prefix + assets[i].ID
		rules[i].AssetID = assets[i].ID
	}
}

// merge concatenates slices from two voter sets.
func merge(
	r1, r2 []VexRule, o1, o2 []Organization, p1, p2 []Project, a1, a2 []Asset,
) ([]VexRule, []Organization, []Project, []Asset) {
	return append(r1, r2...), append(o1, o2...), append(p1, p2...), append(a1, a2...)
}

// Helper function tests

func TestFindVexRuleByID(t *testing.T) {
	rules := []VexRule{
		makeVexRule("rule-1", "a1", testAssessmentPrimary),
		makeVexRule("rule-2", "a2", testAssessmentSecondary),
		makeVexRule("rule-3", "a3", testAssessmentSecondary),
	}

	found, ok := findVexRuleByID("rule-1", rules)
	assert.True(t, ok)
	assert.Equal(t, "a1", found.AssetID)
	assert.Equal(t, testAssessmentPrimary, found.Assessment)

	found, ok = findVexRuleByID("rule-3", rules)
	assert.True(t, ok)
	assert.Equal(t, "a3", found.AssetID)
	assert.Equal(t, testAssessmentSecondary, found.Assessment)

	_, ok = findVexRuleByID("nonexistent", rules)
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
	result, err := CrowdsourcedVexing(rules, orgs, projects, assets)
	require.NoError(t, err)
	assert.Equal(t, "rule-uniform", result.ID)
	assert.Equal(t, testAssessmentPrimary, result.Assessment)
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

			result, err := CrowdsourcedVexing(allR, allO, allP, allA)
			require.NoError(t, err)
			assert.Equal(t, "rule-high", result.ID, "higher trust score votes should win")
		})
	}
}

// This tests if the higher trust score between organization and project is used
// If the organization trust score is used, the malicious rule should win the vote
// This test assumes that TestCrowdsourcedVexing_HigherTrustscoreWins passed
func TestCrowdsourcedVexing_UsesMaxOfOrgAndProjectTrustscore(t *testing.T) {
	var rules []VexRule
	var orgs []Organization
	var projects []Project
	var assets []Asset

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

	result, err := CrowdsourcedVexing(rules, orgs, projects, assets)
	require.NoError(t, err)
	assert.Equal(t, "rule-good", result.ID, "the higher project trust score should be used over the organization trust score")
}

func TestCrowdsourcedVexing_ProjectsOnly(t *testing.T) {
	var rules []VexRule
	var orgs []Organization
	var projects []Project
	var assets []Asset

	var mRules []VexRule
	var mOrgs []Organization
	var mProjects []Project
	var mAssets []Asset

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

	result, err := CrowdsourcedVexing(allR, allO, allP, allA)
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

		result, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-high", result.ID, "quality should beat quantity")
	})

	t.Run("many moderate-trust voters beat few high-trust voters", func(t *testing.T) {
		// 4 voters at 0.5 = 2.0  vs  10 voters at 0.3 = 3.0
		fewR, fewO, fewP, fewA := generateDistinctVoters(4, "rule-few", testAssessmentPrimary, 0.5, oldOrg())
		manyR, manyO, manyP, manyA := generateDistinctVoters(10, "rule-many", testAssessmentSecondary, 0.3, oldOrg())
		rekey("many-", manyR, manyO, manyP, manyA)
		allR, allO, allP, allA := merge(fewR, manyR, fewO, manyO, fewP, manyP, fewA, manyA)

		result, err := CrowdsourcedVexing(allR, allO, allP, allA)
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

		rule, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-old", rule.ID)
	})

	t.Run("boundary age is accepted", func(t *testing.T) {
		boundary := time.Now().Add(-time.Duration(minOrganizationAgeInDays)*24*time.Hour - time.Minute)
		oldR, oldO, oldP, oldA := generateDistinctVoters(3, "rule-old", testAssessmentPrimary, 0.1, oldOrg())
		yngR, yngO, yngP, yngA := generateDistinctVoters(3, "rule-young", testAssessmentSecondary, 0.8, boundary)
		rekey("yng-", yngR, yngO, yngP, yngA)
		allR, allO, allP, allA := merge(oldR, yngR, oldO, yngO, oldP, yngP, oldA, yngA)

		rule, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-young", rule.ID)
	})
}

// [Mitigation 15] Minimum voter threshold must be enforced.
func TestSecurity_MinVoterThreshold(t *testing.T) {
	t.Run("exactly threshold voters succeeds", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		result, err := CrowdsourcedVexing(rules, orgs, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, "rule-a", result.ID)
	})

	t.Run("threshold minus one returns error", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold-1, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(rules, orgs, projects, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("zero voters returns error", func(t *testing.T) {
		_, err := CrowdsourcedVexing([]VexRule{}, []Organization{}, []Project{}, []Asset{})
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})
}

// [Mitigation 20] Replay protection — duplicate votes from same org+project are ignored.
func TestSecurity_ReplayProtection(t *testing.T) {
	t.Run("duplicate org and project only counts once", func(t *testing.T) {
		org := makeOrg("replay-org", 0.9, oldOrg())
		project := makeProject("replay-proj", "replay-org", 0.9)
		asset := makeAsset("replay-asset", "replay-proj")

		var rules []VexRule
		for range 5 {
			rules = append(rules, makeVexRule("rule-a", asset.ID, testAssessmentPrimary))
		}

		_, err := CrowdsourcedVexing(rules, []Organization{org}, []Project{project}, []Asset{asset})
		assert.ErrorIs(t, err, ErrNoRecommendation, "5 duplicate votes from same org+project should count as 1 vote below threshold")
	})

	t.Run("same org different projects count separately", func(t *testing.T) {
		org := makeOrg("shared-org", 0.8, oldOrg())

		var rules []VexRule
		var projects []Project
		var assets []Asset
		for i := range 5 {
			s := fmt.Sprintf("%d", i)
			projID := "diff-proj-" + s
			assetID := "diff-asset-" + s
			projects = append(projects, makeProject(projID, "shared-org", 0.8))
			assets = append(assets, makeAsset(assetID, projID))
			rules = append(rules, makeVexRule("rule-a", assetID, testAssessmentPrimary))
		}

		result, err := CrowdsourcedVexing(rules, []Organization{org}, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, testAssessmentPrimary, result.Assessment)
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
			_, err := CrowdsourcedVexing(rules, orgs, projects, assets)
			assert.ErrorIs(t, err, ErrNoRecommendation, "assessment '%s' should not produce valid votes", bad)
		})
	}
}

// Negative trust scores should not produce a winning vote.
func TestSecurity_NegativeTrustscores(t *testing.T) {
	t.Run("negative trust", func(t *testing.T) {
		rules, orgs, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, -1.0, oldOrg())
		_, err := CrowdsourcedVexing(rules, orgs, projects, assets)
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

		_, err := CrowdsourcedVexing(allR, allO, allP, allA)
		assert.ErrorIs(t, err, ErrNoRecommendation, "tie should return no VexRule")
	})
}

// [Mitigation 8] Diminishing returns: same user creating many orgs gets less vote weight.
func TestSecurity_DiminishingReturns(t *testing.T) {

	t.Run("same creator multiple orgs diminished vs distinct creators", func(t *testing.T) {
		var sameRules []VexRule
		var sameOrgs []Organization
		var sameProjs []Project
		var sameAssets []Asset
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

		result, err := CrowdsourcedVexing(allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, "rule-distinct", result.ID,
			"distinct creators should outweigh a single creator with many orgs due to diminishing returns")
	})

	t.Run("creators on the same trustlevel can compete with each other using vote volume", func(t *testing.T) {
		distinct1R, distinct1O, distinct1P, distinct1A := generateDistinctVoters(4, "rule-1", testAssessmentPrimary, 0.8, oldOrg())
		distinct2R, distinct2O, distinct2P, distinct2A := generateDistinctVoters(5, "rule-2", testAssessmentSecondary, 0.8, oldOrg())
		rekey("dist-", distinct1R, distinct1O, distinct1P, distinct1A)

		allR, allO, allP, allA := merge(distinct2R, distinct1R, distinct2O, distinct1O, distinct2P, distinct1P, distinct2A, distinct1A)

		result, err := CrowdsourcedVexing(allR, allO, allP, allA)
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
		_, err := CrowdsourcedVexing(rules, orgs, projects, []Asset{})
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("missing projects", func(t *testing.T) {
		rules, orgs, _, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(rules, orgs, []Project{}, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("missing organizations", func(t *testing.T) {
		rules, _, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(rules, []Organization{}, projects, assets)
		assert.ErrorIs(t, err, ErrNoRecommendation)
	})

	t.Run("no rules returns error", func(t *testing.T) {
		_, orgs, projects, assets := generateDistinctVoters(5, "rule-a", testAssessmentPrimary, 0.8, oldOrg())
		_, err := CrowdsourcedVexing([]VexRule{}, orgs, projects, assets)
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

	result, err := CrowdsourcedVexing(allR, allO, allP, allA)
	require.NoError(t, err)
	assert.Equal(t, testAssessmentSecondary, result.Assessment, "even very small positive trust should produce a result")
}
