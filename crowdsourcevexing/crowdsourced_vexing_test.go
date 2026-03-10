package crowdsourcevexing

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test constants and helpers ---

var testCVE = CVE{CVE: "CVE-2025-TEST"}

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

func makeVexRule(path []string, cve CVE, assetID, assessment string) VexRule {
	return VexRule{
		PathPattern: path,
		CVE:         cve,
		AssetID:     assetID,
		Assessment:  assessment,
		Reasoning:   "test reasoning",
	}
}

// wildcardFor returns a wildcard pattern that matches any dependency path
// containing the leaf element of the given path.
func wildcardFor(path []string) []string {
	return []string{"*", path[len(path)-1]}
}

// generateDistinctVoters creates n distinct org/project/asset chains plus
// matching VexRules for the given pattern and assessment.
// Each voter gets a unique creator to avoid diminishing-returns penalties.
func generateDistinctVoters(n int, pattern []string, cve CVE, assessment string, trustscore float64, createdAt time.Time) ([]VexRule, []Organization, []Project, []Asset) {
	var rules []VexRule
	var orgs []Organization
	var projects []Project
	var assets []Asset

	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		orgID := "org-" + suffix
		projID := "proj-" + suffix
		assetID := "asset-" + suffix

		orgs = append(orgs, makeOrgWithCreator(orgID, trustscore, createdAt, "creator-"+suffix))
		projects = append(projects, makeProject(projID, orgID, trustscore))
		assets = append(assets, makeAsset(assetID, projID))
		rules = append(rules, makeVexRule(pattern, cve, assetID, assessment))
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

// --- Dependency paths ---

var shallowPath = []string{"ROOT", "packageA@1.0.0"}
var mediumPath = []string{"ROOT", "packageA@1.0.0", "packageB@2.0.0"}
var deepPath = []string{"ROOT", "frameworkX@3.0.0", "libY@1.2.0", "utilZ@0.5.0", "coreW@4.1.0"}
var veryDeepPath = []string{"ROOT", "app@1.0.0", "framework@2.0.0", "middleware@3.0.0", "adapter@4.0.0", "driver@5.0.0", "native@6.0.0"}

var branchPathA = []string{"ROOT", "frameworkX@3.0.0", "libY@1.2.0", "pluginA@1.0.0"}
var branchPathB = []string{"ROOT", "frameworkX@3.0.0", "libY@1.2.0", "pluginB@2.0.0"}
var branchPathC = []string{"ROOT", "frameworkX@3.0.0", "adapterZ@0.1.0"}

// Helper function tests

func mustMatch(t *testing.T, path, pattern []string) bool {
	t.Helper()
	match, err := pathPatternMatchesPath(path, pattern)
	require.NoError(t, err)
	return match
}

func TestPathPatternMatchesPath(t *testing.T) {
	t.Run("wildcard pattern matches path containing leaf", func(t *testing.T) {
		assert.True(t, mustMatch(t, shallowPath, []string{"*", "packageA@1.0.0"}))
		assert.True(t, mustMatch(t, deepPath, []string{"*", "utilZ@0.5.0"}))
		assert.True(t, mustMatch(t, veryDeepPath, []string{"*", "adapter@4.0.0"}))
	})

	t.Run("wildcard pattern matches path containing start and leaf", func(t *testing.T) {
		assert.True(t, mustMatch(t, mediumPath, []string{"ROOT", "*", "packageA@1.0.0"}))
		assert.True(t, mustMatch(t, deepPath, []string{"ROOT", "*", "coreW@4.1.0"}))
		assert.True(t, mustMatch(t, veryDeepPath, []string{"ROOT", "*", "native@6.0.0"}))
	})

	t.Run("wildcard pattern matches path containing intermediate elements", func(t *testing.T) {
		assert.True(t, mustMatch(t, shallowPath, []string{"*", "packageA@1.0.0"}))
		assert.True(t, mustMatch(t, deepPath, []string{"*", "utilZ@0.5.0"}))
		assert.True(t, mustMatch(t, veryDeepPath, []string{"*", "adapter@4.0.0"}))
	})

	t.Run("wildcard pattern matches path containing intermediate start and end elements", func(t *testing.T) {
		assert.True(t, mustMatch(t, deepPath, []string{"frameworkX@3.0.0", "*", "utilZ@0.5.0"}))
		assert.True(t, mustMatch(t, veryDeepPath, []string{"app@1.0.0", "*", "adapter@4.0.0"}))
	})

	t.Run("wildcard pattern does not match if last element absent", func(t *testing.T) {
		assert.False(t, mustMatch(t, shallowPath, []string{"*", "nonexistent@0.0.0"}))
		assert.False(t, mustMatch(t, deepPath, []string{"*", "nonexistent@1.0.0"}))
		assert.False(t, mustMatch(t, shallowPath, []string{"ROOT", "*", "nonexistent@0.0.0"}))
		assert.False(t, mustMatch(t, deepPath, []string{"ROOT", "*", "nonexistent@1.0.0"}))
		assert.False(t, mustMatch(t, deepPath, []string{"nonexistent@1.0.0", "*", "utilZ@0.5.0"}))
		assert.False(t, mustMatch(t, veryDeepPath, []string{"nonexistent@0.0.0", "*", "middleware@3.0.0"}))
	})

	t.Run("single element pattern matches if element in path", func(t *testing.T) {
		assert.True(t, mustMatch(t, shallowPath, []string{"packageA@1.0.0"}))
		assert.True(t, mustMatch(t, deepPath, []string{"coreW@4.1.0"}))
		assert.True(t, mustMatch(t, deepPath, []string{"ROOT"}))
		assert.True(t, mustMatch(t, deepPath, []string{"utilZ@0.5.0"}))
		assert.True(t, mustMatch(t, veryDeepPath, []string{"middleware@3.0.0"}))
	})
}

func TestPathPatternMatchLength(t *testing.T) {

	t.Run("wildcard returns endIndex + 1", func(t *testing.T) {
		length, err := pathPatternMatchLength(deepPath, []string{"libY@1.2.0", "*", "coreW@4.1.0"})
		assert.NoError(t, err)
		assert.Equal(t, 3, length)
	})

	t.Run("wildcard returns endIndex + 1", func(t *testing.T) {
		length, err := pathPatternMatchLength(deepPath, []string{"*", "coreW@4.1.0"})
		assert.NoError(t, err)
		assert.Equal(t, 5, length)
	})

	t.Run("wildcard returns endIndex + 1", func(t *testing.T) {
		length, err := pathPatternMatchLength(veryDeepPath, []string{"adapter@4.0.0"})
		assert.NoError(t, err)
		assert.Equal(t, 1, length)
	})

	t.Run("wildcard returns endIndex + 1", func(t *testing.T) {
		length, err := pathPatternMatchLength(veryDeepPath, []string{"ROOT"})
		assert.NoError(t, err)
		assert.Equal(t, 1, length)
	})

	t.Run("wildcard with intermediate element", func(t *testing.T) {
		length, err := pathPatternMatchLength(deepPath, []string{"*", "utilZ@0.5.0"})
		assert.NoError(t, err)
		assert.Equal(t, 4, length)
	})

	t.Run("wildcard with intermediate element", func(t *testing.T) {
		length, err := pathPatternMatchLength(veryDeepPath, []string{"*"})
		assert.NoError(t, err)
		assert.Equal(t, len(veryDeepPath), length)
	})

	t.Run("missing end element returns error", func(t *testing.T) {
		_, err := pathPatternMatchLength(deepPath, []string{"*", "nonexistent@0.0.0"})
		assert.Error(t, err)
	})
}

func TestPathToString(t *testing.T) {
	rule := makeVexRule([]string{"*", "pkg@1"}, testCVE, "a1", FalsePositive)
	assert.Equal(t, "*-->pkg@1-->false-positive", PathToString(rule))

	ruleShort := makeVexRule([]string{"pkg@1", "*", "pkg@2"}, testCVE, "a1", FalsePositive)
	assert.Equal(t, "pkg@1-->*-->pkg@2-->false-positive", PathToString(ruleShort))

	ruleAff := makeVexRule([]string{"*", "pkg@1"}, testCVE, "a1", Affected)
	assert.NotEqual(t, PathToString(rule), PathToString(ruleAff))

	deepRule := makeVexRule(deepPath, testCVE, "a1", Affected)
	assert.Equal(t, "ROOT-->frameworkX@3.0.0-->libY@1.2.0-->utilZ@0.5.0-->coreW@4.1.0-->affected", PathToString(deepRule))
}

func TestFindVexRuleFromPath(t *testing.T) {
	rules := []VexRule{
		makeVexRule([]string{"*", "pkg@1"}, testCVE, "a1", FalsePositive),
		makeVexRule([]string{"*", "pkg@2"}, testCVE, "a2", Affected),
		makeVexRule([]string{"*", "pkg@3"}, testCVE, "a3", Affected),
		makeVexRule([]string{"*", "pkg@1"}, testCVE, "a4", Affected),
		makeVexRule([]string{"pkg@1", "*", "pkg@2"}, testCVE, "a5", Affected),
		makeVexRule([]string{"pkg@2", "*", "pkg@1"}, testCVE, "a6", Affected),
		makeVexRule([]string{"pkg@1", "*", "pkg@3"}, testCVE, "a7", Affected),
	}

	found, ok := findVexRuleFromPath(PathToString(rules[0]), rules)
	assert.True(t, ok)
	assert.Equal(t, "a1", found.AssetID)
	assert.Equal(t, FalsePositive, found.Assessment)

	found, ok = findVexRuleFromPath(PathToString(rules[2]), rules)
	assert.True(t, ok)
	assert.Equal(t, "a3", found.AssetID)
	assert.Equal(t, Affected, found.Assessment)

	found, ok = findVexRuleFromPath(PathToString(rules[6]), rules)
	assert.True(t, ok)
	assert.Equal(t, "a7", found.AssetID)
	assert.Equal(t, Affected, found.Assessment)

	_, ok = findVexRuleFromPath("nonexistent", rules)
	assert.False(t, ok)
}

func TestUserVoteTracker(t *testing.T) {
	tracker := newUserVoteTracker()
	orgAlice := Organization{CreatedBy: "alice"}
	orgBob := Organization{CreatedBy: "bob"}

	assert.Equal(t, 1.0, tracker.recordVoteAndGetFactor(orgAlice))
	assert.Equal(t, 0.1, tracker.recordVoteAndGetFactor(orgAlice))
	assert.Equal(t, 1.0, tracker.recordVoteAndGetFactor(orgBob))
	assert.Equal(t, 0.01, tracker.recordVoteAndGetFactor(orgAlice))
}

// CrowdsourcedVexing

// This test covers that even in a uniform vote, the correct rule is recommended and no errors are thrown
func TestCrowdsourcedVexing_UniformVote(t *testing.T) {
	cases := []struct {
		name       string
		path       []string
		assessment string
	}{
		{"false-positive shallow", shallowPath, FalsePositive},
		{"false-positive medium", mediumPath, FalsePositive},
		{"false-positive deep", deepPath, FalsePositive},
		{"false-positive very deep", veryDeepPath, FalsePositive},
		{"affected shallow", shallowPath, Affected},
		{"affected medium", mediumPath, Affected},
		{"affected deep", deepPath, Affected},
		{"affected very deep", veryDeepPath, Affected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pattern := wildcardFor(tc.path)
			rules, orgs, projects, assets := generateDistinctVoters(5, pattern, testCVE, tc.assessment, 0.8, oldOrg())
			result, err := CrowdsourcedVexing(tc.path, testCVE, rules, orgs, projects, assets)
			require.NoError(t, err)
			assert.Equal(t, tc.assessment, result.Assessment)
			assert.Equal(t, pattern, result.PathPattern)
		})
	}
}

// Trust score behavior

// This test covers if higher trust score voters can outweigh lower trust score voters, when the number of votes is equal
func TestCrowdsourcedVexing_HigherTrustscoreWins(t *testing.T) {
	cases := []struct {
		name     string
		path     []string
		lowTrust float64
		hiTrust  float64
	}{
		{"0.1 vs 0.9 shallow", shallowPath, 0.1, 0.9},
		{"0.3 vs 0.7 medium", mediumPath, 0.3, 0.7},
		{"0.1 vs 0.5 deep", deepPath, 0.1, 0.5},
		{"0.5 vs 0.9 very deep", veryDeepPath, 0.5, 0.9},
		{"0.01 vs 0.99 deep", deepPath, 0.01, 0.99},
		{"0.5 vs 0.51 deep", deepPath, 0.5, 0.51},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pattern := wildcardFor(tc.path)
			lowR, lowO, lowP, lowA := generateDistinctVoters(4, pattern, testCVE, Affected, tc.lowTrust, oldOrg())
			hiR, hiO, hiP, hiA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, tc.hiTrust, oldOrg())
			rekey("hi-", hiR, hiO, hiP, hiA)
			allR, allO, allP, allA := merge(lowR, hiR, lowO, hiO, lowP, hiP, lowA, hiA)

			result, err := CrowdsourcedVexing(tc.path, testCVE, allR, allO, allP, allA)
			require.NoError(t, err)
			assert.Equal(t, FalsePositive, result.Assessment, "higher trust score votes should win")
		})
	}
}

// This tests if the higher trust score between organization and project is used
// If the organization trust score is used, the malicious rule should win the vote
// This test assumes that TestCrowdsourcedVexing_HigherTrustscoreWins passed
func TestCrowdsourcedVexing_UsesMaxOfOrgAndProjectTrustscore(t *testing.T) {
	pattern := wildcardFor(shallowPath)

	var rules []VexRule
	var orgs []Organization
	var projects []Project
	var assets []Asset

	for i := 0; i < 5; i++ {
		orgs = append(orgs, makeOrgWithCreator("org-mal", 0.3, oldOrg(), "creator-mal"))
		projects = append(projects, makeProject("proj-mal", "org-mal", 0.3))
		assets = append(assets, makeAsset("asset-mal", "proj-mal"))
		rules = append(rules, makeVexRule(pattern, testCVE, "asset-mal", Affected))
	}

	for i := 0; i < 5; i++ {
		s := fmt.Sprintf("%d", i)
		orgs = append(orgs, makeOrgWithCreator("org-"+s, 0.1, oldOrg(), "creator-"+s))
		projects = append(projects, makeProject("proj-"+s, "org-"+s, 0.9))
		assets = append(assets, makeAsset("asset-"+s, "proj-"+s))
		rules = append(rules, makeVexRule(pattern, testCVE, "asset-"+s, FalsePositive))
	}

	result, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, projects, assets)
	require.NoError(t, err)
	assert.Equal(t, FalsePositive, result.Assessment)
}

func TestCrowdsourcedVexing_QuantityVsQuality(t *testing.T) {
	t.Run("few high-trust voters beat many low-trust voters", func(t *testing.T) {
		// 4 voters at 0.9 = 3.6  vs  10 voters at 0.1 = 1.0
		pattern := wildcardFor(mediumPath)
		hiR, hiO, hiP, hiA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 0.9, oldOrg())
		loR, loO, loP, loA := generateDistinctVoters(10, pattern, testCVE, Affected, 0.1, oldOrg())
		rekey("lo-", loR, loO, loP, loA)
		allR, allO, allP, allA := merge(hiR, loR, hiO, loO, hiP, loP, hiA, loA)

		result, err := CrowdsourcedVexing(mediumPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment, "quality should beat quantity")
	})

	t.Run("many moderate-trust voters beat few high-trust voters", func(t *testing.T) {
		// 4 voters at 0.5 = 2.0  vs  10 voters at 0.3 = 3.0
		pattern := wildcardFor(deepPath)
		fewR, fewO, fewP, fewA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 0.5, oldOrg())
		manyR, manyO, manyP, manyA := generateDistinctVoters(10, pattern, testCVE, Affected, 0.3, oldOrg())
		rekey("many-", manyR, manyO, manyP, manyA)
		allR, allO, allP, allA := merge(fewR, manyR, fewO, manyO, fewP, manyP, fewA, manyA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment, "enough moderate-trust quantity can outweigh fewer high-trust voters")
	})
}

// ============================================================
// Security / Mitigation tests
// ============================================================

// [Mitigation 10,11] Organization must be older than minOrganizationAgeInDays.
func TestSecurity_MinOrganizationAge(t *testing.T) {
	t.Run("young organizations are rejected", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		oldR, oldO, oldP, oldA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 0.1, oldOrg())
		yngR, yngO, yngP, yngA := generateDistinctVoters(4, pattern, testCVE, Affected, 0.8, youngOrg())
		rekey("yng-", yngR, yngO, yngP, yngA)
		allR, allO, allP, allA := merge(oldR, yngR, oldO, yngO, oldP, yngP, oldA, yngA)

		rule, err := CrowdsourcedVexing(shallowPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, rule.Assessment)
	})

	t.Run("boundary age is accepted", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		boundary := time.Now().Add(-time.Duration(minOrganizationAgeInDays)*24*time.Hour - time.Minute)
		oldR, oldO, oldP, oldA := generateDistinctVoters(3, pattern, testCVE, FalsePositive, 0.1, oldOrg())
		yngR, yngO, yngP, yngA := generateDistinctVoters(3, pattern, testCVE, Affected, 0.8, boundary)
		rekey("yng-", yngR, yngO, yngP, yngA)
		allR, allO, allP, allA := merge(oldR, yngR, oldO, yngO, oldP, yngP, oldA, yngA)

		rule, err := CrowdsourcedVexing(shallowPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, rule.Assessment)
	})
}

// [Mitigation 15] Minimum voter threshold must be enforced.
func TestSecurity_MinVoterThreshold(t *testing.T) {
	t.Run("exactly threshold voters succeeds", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		result, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment)
	})

	t.Run("threshold minus one returns error", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		rules, orgs, projects, assets := generateDistinctVoters(minVoterThreshold-1, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, projects, assets)
		assert.Error(t, err)
	})

	t.Run("zero voters returns error", func(t *testing.T) {
		_, err := CrowdsourcedVexing(shallowPath, testCVE, []VexRule{}, []Organization{}, []Project{}, []Asset{})
		assert.Error(t, err)
	})
}

// [Mitigation 20] Replay protection — duplicate votes from same org+project are ignored.
func TestSecurity_ReplayProtection(t *testing.T) {
	t.Run("duplicate org and project only counts once", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		org := makeOrg("replay-org", 0.9, oldOrg())
		project := makeProject("replay-proj", "replay-org", 0.9)

		var rules []VexRule
		var assets []Asset
		for i := 0; i < 5; i++ {
			assetID := fmt.Sprintf("replay-asset-%d", i)
			assets = append(assets, makeAsset(assetID, "replay-proj"))
			rules = append(rules, makeVexRule(pattern, testCVE, assetID, FalsePositive))
		}

		_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, []Organization{org}, []Project{project}, assets)
		assert.Error(t, err, "5 duplicate votes from same org+project should count as 1 vote below threshold")
	})

	t.Run("same org different projects count separately", func(t *testing.T) {
		pattern := wildcardFor(shallowPath)
		org := makeOrg("shared-org", 0.8, oldOrg())

		var rules []VexRule
		var projects []Project
		var assets []Asset
		for i := 0; i < 5; i++ {
			s := fmt.Sprintf("%d", i)
			projID := "diff-proj-" + s
			assetID := "diff-asset-" + s
			projects = append(projects, makeProject(projID, "shared-org", 0.8))
			assets = append(assets, makeAsset(assetID, projID))
			rules = append(rules, makeVexRule(pattern, testCVE, assetID, FalsePositive))
		}

		result, err := CrowdsourcedVexing(shallowPath, testCVE, rules, []Organization{org}, projects, assets)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment)
	})

	t.Run("replay protection on deep path", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		org := makeOrg("deep-replay-org", 0.9, oldOrg())
		project := makeProject("deep-replay-proj", "deep-replay-org", 0.9)

		var rules []VexRule
		var assets []Asset
		for i := 0; i < 10; i++ {
			assetID := fmt.Sprintf("deep-replay-asset-%d", i)
			assets = append(assets, makeAsset(assetID, "deep-replay-proj"))
			rules = append(rules, makeVexRule(pattern, testCVE, assetID, FalsePositive))
		}

		_, err := CrowdsourcedVexing(deepPath, testCVE, rules, []Organization{org}, []Project{project}, assets)
		assert.Error(t, err, "duplicate votes from same org+project should count as 1 even on deep paths")
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
			pattern := wildcardFor(deepPath)
			rules, orgs, projects, assets := generateDistinctVoters(5, pattern, testCVE, bad, 0.8, oldOrg())
			_, err := CrowdsourcedVexing(deepPath, testCVE, rules, orgs, projects, assets)
			assert.Error(t, err, "assessment '%s' should not produce valid votes on deep path", bad)
		})
	}
}

// [Mitigation 13] Trust score weighting — zero trust should not contribute.
func TestSecurity_TrustscoreWeighting(t *testing.T) {
	t.Run("zero trust score contributes zero weight", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		zeroR, zeroO, zeroP, zeroA := generateDistinctVoters(4, pattern, testCVE, Affected, 0.0, oldOrg())
		highR, highO, highP, highA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 1.0, oldOrg())
		rekey("hi-", highR, highO, highP, highA)
		allR, allO, allP, allA := merge(zeroR, highR, zeroO, highO, zeroP, highP, zeroA, highA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment)
	})
}

// Negative trust scores should not produce a winning vote.
func TestSecurity_NegativeTrustscores(t *testing.T) {
	t.Run("negative trust on deep path", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		rules, orgs, projects, assets := generateDistinctVoters(5, pattern, testCVE, FalsePositive, -1.0, oldOrg())
		_, err := CrowdsourcedVexing(deepPath, testCVE, rules, orgs, projects, assets)
		assert.Error(t, err)
	})
}

// [Mitigation 31] Tie-breaking — "affected" wins deterministically when votes are equal.
func TestSecurity_TieBreaking(t *testing.T) {
	t.Run("same rule different assessment tie - favors affected", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		affR, affO, affP, affA := generateDistinctVoters(4, pattern, testCVE, Affected, 0.5, oldOrg())
		fpR, fpO, fpP, fpA := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 0.5, oldOrg())
		rekey("fp-", fpR, fpO, fpP, fpA)
		allR, allO, allP, allA := merge(affR, fpR, affO, fpO, affP, fpP, affA, fpA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment,
			"tie should favor affected as the more secure option on deep path")
	})

	t.Run("different rule same assessment tie - favors more coverage", func(t *testing.T) {
		longPattern := wildcardFor(deepPath)
		shortPattern := wildcardFor([]string{"*", "libY@1.2.0"})
		lPR, lPO, lPP, lPA := generateDistinctVoters(4, longPattern, testCVE, Affected, 0.5, oldOrg())
		sPR, sPO, sPP, sPA := generateDistinctVoters(4, shortPattern, testCVE, Affected, 0.5, oldOrg())
		rekey("sP-", lPR, lPO, lPP, lPA)
		allR, allO, allP, allA := merge(lPR, sPR, lPO, sPO, lPP, sPP, lPA, sPA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, longPattern, result.PathPattern,
			"tie should favor affected as the more secure option on deep path")
	})
}

// [Mitigation 8] Diminishing returns: same user creating many orgs gets less vote weight.
func TestSecurity_DiminishingReturns(t *testing.T) {

	t.Run("same creator multiple orgs diminished vs distinct creators", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		var sameRules []VexRule
		var sameOrgs []Organization
		var sameProjs []Project
		var sameAssets []Asset
		for i := 0; i < 100; i++ {
			s := fmt.Sprintf("%d", i)
			sameOrgs = append(sameOrgs, makeOrgWithCreator("deep-same-org-"+s, 0.3, oldOrg(), "deep-single-user"))
			sameProjs = append(sameProjs, makeProject("deep-same-proj-"+s, "deep-same-org-"+s, 0.3))
			sameAssets = append(sameAssets, makeAsset("deep-same-asset-"+s, "deep-same-proj-"+s))
			sameRules = append(sameRules, makeVexRule(pattern, testCVE, "deep-same-asset-"+s, FalsePositive))
		}

		distinctR, distinctO, distinctP, distinctA := generateDistinctVoters(1, pattern, testCVE, Affected, 0.9, oldOrg())
		rekey("dist-", distinctR, distinctO, distinctP, distinctA)

		allR, allO, allP, allA := merge(sameRules, distinctR, sameOrgs, distinctO, sameProjs, distinctP, sameAssets, distinctA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment,
			"distinct creators should outweigh a single creator with many orgs due to diminishing returns")
	})

	t.Run("Rounding error edge case: same creator multiple orgs diminished vs distinct creators", func(t *testing.T) {
		pattern := wildcardFor(deepPath)
		var sameRules []VexRule
		var sameOrgs []Organization
		var sameProjs []Project
		var sameAssets []Asset
		for i := 0; i < 100; i++ {
			s := fmt.Sprintf("%d", i)
			sameOrgs = append(sameOrgs, makeOrgWithCreator("deep-same-org-"+s, 0.9, oldOrg(), "deep-single-user"))
			sameProjs = append(sameProjs, makeProject("deep-same-proj-"+s, "deep-same-org-"+s, 0.9))
			sameAssets = append(sameAssets, makeAsset("deep-same-asset-"+s, "deep-same-proj-"+s))
			sameRules = append(sameRules, makeVexRule(pattern, testCVE, "deep-same-asset-"+s, Affected))
		}

		distinctR, distinctO, distinctP, distinctA := generateDistinctVoters(1, pattern, testCVE, FalsePositive, 0.9, oldOrg())
		rekey("dist-", distinctR, distinctO, distinctP, distinctA)

		allR, allO, allP, allA := merge(sameRules, distinctR, sameOrgs, distinctO, sameProjs, distinctP, sameAssets, distinctA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment,
			"distinct creators should outweigh a single creator with many orgs due to diminishing returns")
	})

	t.Run("many same-creator orgs cannot exceed convergence limit", func(t *testing.T) {
		pattern := wildcardFor(deepPath)

		distinct1R, distinct1O, distinct1P, distinct1A := generateDistinctVoters(4, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		distinct2R, distinct2O, distinct2P, distinct2A := generateDistinctVoters(5, pattern, testCVE, Affected, 0.8, oldOrg())
		rekey("dist-", distinct1R, distinct1O, distinct1P, distinct1A)

		allR, allO, allP, allA := merge(distinct2R, distinct1R, distinct2O, distinct1O, distinct2P, distinct1P, distinct2A, distinct1A)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment,
			"20 same-creator votes (≈1.0) should not outweigh 4 distinct voters (2.0)")
	})
}

// Votes for paths not matching the dependency path must be ignored.
func TestSecurity_UnrelatedPathsIgnored(t *testing.T) {
	t.Run("unrelated paths on shallow query", func(t *testing.T) {
		validPattern := wildcardFor(shallowPath)
		NoMatchPattern := []string{"*", "nonexistent@9.9.9"}

		validR, validO, validP, validA := generateDistinctVoters(5, validPattern, testCVE, FalsePositive, 0.9, oldOrg())
		nMR, nMO, nMP, nMA := generateDistinctVoters(10, NoMatchPattern, testCVE, Affected, 0.9, oldOrg())
		rekey("nM-", nMR, nMO, nMP, nMA)
		allR, allO, allP, allA := merge(validR, nMR, validO, nMO, validP, nMP, validA, nMA)

		result, err := CrowdsourcedVexing(shallowPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment,
			"only votes for matching paths should count")
	})

	t.Run("unrelated deep paths ignored when querying different deep path", func(t *testing.T) {
		validPattern := wildcardFor(deepPath)
		noMatchPattern := []string{"*", "leaf@4.0.0"}

		validR, validO, validP, validA := generateDistinctVoters(5, validPattern, testCVE, Affected, 0.9, oldOrg())
		nMR, nMO, nMP, nMA := generateDistinctVoters(10, noMatchPattern, testCVE, FalsePositive, 1.0, oldOrg())
		rekey("nM-", nMR, nMO, nMP, nMA)
		allR, allO, allP, allA := merge(validR, nMR, validO, nMO, validP, nMP, validA, nMA)

		result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment)
	})
}

// ============================================================
// Edge cases
// ============================================================

func TestEdgeCase_CVEMismatch(t *testing.T) {
	pattern := wildcardFor(shallowPath)
	otherCVE := CVE{CVE: "CVE-OTHER"}
	rules, orgs, projects, assets := generateDistinctVoters(5, pattern, otherCVE, FalsePositive, 0.8, oldOrg())
	_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, projects, assets)
	assert.Error(t, err, "rules with non-matching CVE should produce no valid votes")
}

func TestEdgeCase_MissingEntities(t *testing.T) {
	pattern := wildcardFor(shallowPath)

	t.Run("missing assets", func(t *testing.T) {
		rules, orgs, projects, _ := generateDistinctVoters(5, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, projects, []Asset{})
		assert.Error(t, err)
	})

	t.Run("missing projects", func(t *testing.T) {
		rules, orgs, _, assets := generateDistinctVoters(5, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, orgs, []Project{}, assets)
		assert.Error(t, err)
	})

	t.Run("missing organizations", func(t *testing.T) {
		rules, _, projects, assets := generateDistinctVoters(5, pattern, testCVE, FalsePositive, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(shallowPath, testCVE, rules, []Organization{}, projects, assets)
		assert.Error(t, err)
	})

	t.Run("no rules returns error", func(t *testing.T) {
		_, err := CrowdsourcedVexing(shallowPath, testCVE, []VexRule{}, []Organization{}, []Project{}, []Asset{})
		assert.Error(t, err)
	})
}

func TestEdgeCase_PathNotMatching(t *testing.T) {

	t.Run("all votes are not matching", func(t *testing.T) {
		depPath := []string{"ROOT", "packageA@1.0.0", "packageB@2.0.0"}
		nonMatchingPattern := []string{"*", "nonexistent@1.0.0"}

		rules, orgs, projects, assets := generateDistinctVoters(5, nonMatchingPattern, testCVE, FalsePositive, 0.8, oldOrg())
		_, err := CrowdsourcedVexing(depPath, testCVE, rules, orgs, projects, assets)
		assert.Error(t, err, "rules with non-matching paths should produce no valid votes")
	})

	t.Run("a few votes are not matching, but still enough votes for the algorithm", func(t *testing.T) {
		depPath := []string{"ROOT", "packageA@1.0.0", "packageB@2.0.0"}
		matchingPattern := wildcardFor(depPath)
		nonMatchingPattern := []string{"*", "nonexistent@1.0.0"}

		nMrules, nMorgs, nMprojects, nMassets := generateDistinctVoters(5, nonMatchingPattern, testCVE, FalsePositive, 0.9, oldOrg())
		mRules, mOrgs, mProjects, mAssets := generateDistinctVoters(4, matchingPattern, testCVE, Affected, 0.3, oldOrg())
		rekey("m-", mRules, mOrgs, mProjects, mAssets)

		allRules, allOrgs, allProjects, allAssets := merge(nMrules, mRules, nMorgs, mOrgs, nMprojects, mProjects, nMassets, mAssets)
		result, err := CrowdsourcedVexing(depPath, testCVE, allRules, allOrgs, allProjects, allAssets)
		require.NoError(t, err)
		assert.Equal(t, Affected, result.Assessment, "rules with non-matching paths should produce no valid votes")
	})
}

// Branching paths: votes for one branch should not count for another.
func TestEdgeCase_BranchedPaths(t *testing.T) {
	t.Run("only matching branch counts", func(t *testing.T) {
		patternA := wildcardFor(branchPathA)
		patternB := wildcardFor(branchPathB)

		fpR, fpO, fpP, fpA := generateDistinctVoters(5, patternA, testCVE, FalsePositive, 0.8, oldOrg())
		affR, affO, affP, affA := generateDistinctVoters(5, patternB, testCVE, Affected, 0.9, oldOrg())
		rekey("b-", affR, affO, affP, affA)

		allR, allO, allP, allA := merge(fpR, affR, fpO, affO, fpP, affP, fpA, affA)

		result, err := CrowdsourcedVexing(branchPathA, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result.Assessment, "only votes matching inDependencyPath should count")
	})

	// Tests if overall it is possible in the system to request different recommendations without the system crashing
	t.Run("each branch independent", func(t *testing.T) {
		patternA := wildcardFor(branchPathA)
		patternB := wildcardFor(branchPathB)

		fpR, fpO, fpP, fpA := generateDistinctVoters(5, patternA, testCVE, FalsePositive, 0.8, oldOrg())
		affR, affO, affP, affA := generateDistinctVoters(5, patternB, testCVE, Affected, 0.9, oldOrg())
		rekey("b-", affR, affO, affP, affA)

		allR, allO, allP, allA := merge(fpR, affR, fpO, affO, fpP, affP, fpA, affA)

		resultA, err := CrowdsourcedVexing(branchPathA, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, resultA.Assessment)

		resultB, err := CrowdsourcedVexing(branchPathB, testCVE, allR, allO, allP, allA)
		require.NoError(t, err)
		assert.Equal(t, Affected, resultB.Assessment)
	})
}

// Very small trust scores should still work when enough voters agree.
// This is interesting since this means that the system is not 100% secure against mass-creation attacks
// Trust scores improve the resistance against such attacks, but do not extinguish them completely
// Now the question is, where is the threshold
// Referring back to byzantine generals problem and 50% threshold of etherium
// Application of diminishing returns show by math (exponential decay) that one low trusted user cannot out-vote a high-trusted user
/* 	t.Run("verify diminishing math with trust 0.8", func(t *testing.T) {
	// Directly verify the exponential decay:
	// trust^1 + trust^2 + ... + trust^n < n * trust for n > 1 and 0 < trust < 1
	trust := 0.8
	sameCreatorSum := 0.0
	n := 10
	for i := 1; i <= n; i++ {
		sameCreatorSum += math.Pow(trust, float64(i))
	}
	distinctSum := float64(n) * trust
	assert.Greater(t, distinctSum, sameCreatorSum,
		"n distinct voters should always contribute more than n same-creator voters for trust < 1")
}) */
// So basically a user cannot another user if the trust scores have a differene by 0.1
// But what about multiple users that act as attackers
func TestEdgeCase_VerySmallTrustscores(t *testing.T) {
	pattern := wildcardFor(deepPath)
	rules, orgs, projects, assets := generateDistinctVoters(100, pattern, testCVE, Affected, 0.01, oldOrg())
	tRules, tOrgs, tProjects, tAssets := generateDistinctVoters(1, pattern, testCVE, FalsePositive, 0.99, oldOrg())

	allR, allO, allP, allA := merge(rules, tRules, orgs, tOrgs, projects, tProjects, assets, tAssets)

	result, err := CrowdsourcedVexing(deepPath, testCVE, allR, allO, allP, allA)
	require.NoError(t, err)
	assert.Equal(t, Affected, result.Assessment, "even very small positive trust should produce a result")
}
