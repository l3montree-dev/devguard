package crowdsourcevexing

import (
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"
)

type dependencyNode struct {
	Dependecy string           // Consists of dependecy name and version
	Children  []dependencyNode // Will be [] if node is a leaf
}

type User struct {
	ID string
}

type Asset struct {
	ID        string
	ProjectID string
}

type Organization struct {
	ID         string
	Trustscore float64
	CreatedAt  time.Time
	CreatedBy  string
	UserIDs    []string
}

type Project struct {
	ID             string
	OrganizationID string
	Trustscore     float64
}

const (
	falsePositive = "false-positive"
	affected      = "affected"
)

type VexRule struct {
	PathPattern []string
	AssetID     string
	Reasoning   string
	Assessment  string // Use assesment constants for options, e.g. "false-positive", "affected"
}

type CVE struct {
	CVE string
}

type Vote struct {
	Voters []struct {
		OrganizationID string
		ProjectID      string
	}
	Value float64
}

const (
	minVoterThreshold        = 4
	minOrganizationAgeInDays = 30
)

// [Mitigation 8] userVoteTracker tracks how many times each user has voted
// across all paths to apply diminishing returns on repeated votes.
type userVoteTracker struct {
	voteCounts map[string]int // creatorID -> number of votes cast so far
}

func newUserVoteTracker() *userVoteTracker {
	return &userVoteTracker{
		voteCounts: make(map[string]int),
	}
}

// recordVoteAndGetFactor increments the vote count for the organization's
// creator (CreatedBy) and returns a diminishing factor based on how many
// prior votes that creator already cast.
// Factor: 1/(1+priorVotes) — 1st vote=1.0, 2nd=0.5, 3rd=0.33, etc.
func (t *userVoteTracker) recordVoteAndGetFactor(organization Organization) float64 {
	creator := organization.CreatedBy
	priorVotes := t.voteCounts[creator]
	t.voteCounts[creator]++
	return 1.0 / float64(1+priorVotes)
}

func PathExistsInDependecyTree(inTree map[string]dependencyNode, inPath []string) bool {

	var dfs func(node dependencyNode, index int) bool
	dfs = func(node dependencyNode, index int) bool {

		var pathElement = inPath[index]
		if pathElement != "*" && pathElement != node.Dependecy {
			return false
		}

		if index == len(inPath)-1 {
			return true
		}

		for _, child := range node.Children {
			if dfs(child, index+1) {
				return true
			}
		}
		return false
	}

	return dfs(inTree[""], 0)
}

func PathToString(inVexRule VexRule) string {
	//Adding the assessment to the path will make it possible to distinguish between false-positives and marked-as-affected for the voting count map
	stringPath := strings.Join(append(inVexRule.PathPattern, []string{inVexRule.Assessment}...), "-->")
	return stringPath
}

func findVexRuleFromPath(inVexRulePath string, inVexRules []VexRule) (VexRule, bool) {
	for _, rule := range inVexRules {
		if PathToString(rule) == inVexRulePath {
			return rule, true
		}
	}
	return VexRule{}, false
}

// Missing
// [Mitigation  8] Increasingly decrease the value of each vote created by an organization or project of the same user

// Out of scope mitigations:
// [Mitigation  1] Enforce two-factor authentication for DevGuard users
// [Mitigation  2] Implement token expiry
// [Mitigation  3] Enforce system standards for the use of DevGuard
// [Mitigation  4] Provide best-practice guidelines for environment, setup, and security measures
// [Mitigation  5] Implement account recovery
// [Mitigation  6] Implement emergency account lockdown
// [Mitigation  7] Limit the number of organizations and projects a single user can create
// [Mitigation  9] Implement CAPTCHA to prevent automated bot creation
// [Mitigation 12] Require user/organization verification through an external provider
// [Mitigation 14] Enforce multi-factor checks for account disabling
// [Mitigation 16] Implement visual indicators for crucial acceptance actions
// [Mitigation 17] Implement multi-step dialogue for accepting risks and recommendations
// [Mitigation 18] Verify signature if present (might be overkill with TLS)
// [Mitigation 19] Enforce TLS for all requests
// [Mitigations 21-26] Implement rate limiting and load balancing (DoS protection)
// [Mitigation 27] Enforce multi-factor checks for account disabling (token expiration)
// [Mitigation 28] Enforce two-factor authentication for DevGuard users (auth validation)
// [Mitigation 29] Use well-tested authentication framework

// Some more requirements to consider:
// Application / Creation of vex rules counts as a vote

func CrowdsourcedVexing(inDependencyTree map[string]dependencyNode, inCVE CVE, inVexRules []VexRule, inOrganizations []Organization, inProjects []Project, inAssets []Asset) (VexRule, error) {
	var crowdsourcedVexRule VexRule
	var votes = make(map[string]*Vote)
	var validVotesCount = 0
	// [Mitigation 8] Initialize user vote tracker for diminishing returns
	tracker := newUserVoteTracker()

	// Assumptions
	// - The dependency tree is build and passed as parameter
	// - Dependecy Tree if of form e.g.:
	//   {
	//     "": {Dependecy: "", Children: ["packageA@1.0.0", "packageB@2.0.0"]}, <- Root node is empty string and has as children all top level dependecies
	//     "packageA@1.0.0": {Dependecy: "packageA@1.0.0", Children: []},
	//     "packageB@2.0.0": {Dependecy: "packageB@2.0.0", Children: []},
	//   }
	// - inVexRules contain every VexRule created by a user (full database list)

	// Filtering for VexRules that apply to the dependecy tree
	// Deduplucate VexRules based on organizationn and project to avoid replay
	// (every combination of organization and project will be allow to have one non-contradicting VexRule for a Path submitted)
	for _, rule := range inVexRules {

		// For each VexRule, find organization and project id
		rulePath := PathToString(rule)

		var asset Asset
		for _, asst := range inAssets {
			if asst.ID == rule.AssetID {
				asset = asst
				break
			}
		}
		if asset.ID == "" {
			slog.Error("failed to find asset for VEX rule", "assetID", rule.AssetID)
			continue
		}
		var project Project
		for _, proj := range inProjects {
			if proj.ID == asset.ProjectID {
				project = proj
				break
			}
		}
		if project.ID == "" {
			slog.Error("failed to find project for asset", "projectID", asset.ProjectID)
			continue
		}
		var organization Organization
		for _, org := range inOrganizations {
			if org.ID == project.OrganizationID {
				organization = org
				break
			}
		}
		if organization.ID == "" {
			slog.Error("failed to find organization for project", "organizationID", project.OrganizationID)
			continue
		}

		// [Mitigation 10,11] Minimum organization age check
		if time.Since(organization.CreatedAt) < minOrganizationAgeInDays*24*time.Hour {
			slog.Info("organization does not meet minimum age requirement", "organizationID", organization.ID)
			continue
		}

		if PathExistsInDependecyTree(inDependencyTree, rule.PathPattern) {
			// [Mitigation 30] Input validation — only choosable options allowed, check if reasoning is within options)
			if rule.Assessment == affected || rule.Assessment == falsePositive {
				// [Mitigation 13] Trustscore is used in calculation of crowdsourced VEX rule
				ruleConfidence := math.Max(project.Trustscore, organization.Trustscore)
				// [Mitigation 8] Apply diminishing returns based on user's prior votes across all paths
				diminishingFactor := tracker.recordVoteAndGetFactor(organization)
				ruleConfidence *= diminishingFactor
				// [Mitigation 20] Replay protection via deduplication of VexRules based on datastructure
				if votes[rulePath] != nil && votes[rulePath].Voters != nil {
					alreadyExistingVote := false
					for _, vote := range votes[rulePath].Voters {
						if vote.OrganizationID == organization.ID && vote.ProjectID == project.ID {
							alreadyExistingVote = true
							break
						}
					}
					if !alreadyExistingVote {
						votes[rulePath].Voters = append(votes[rulePath].Voters, struct {
							OrganizationID string
							ProjectID      string
						}{OrganizationID: organization.ID, ProjectID: project.ID})

						votes[rulePath].Value += ruleConfidence
						validVotesCount++
					}
				} else {
					votes[rulePath] = &Vote{
						Voters: []struct {
							OrganizationID string
							ProjectID      string
						}{
							{OrganizationID: organization.ID, ProjectID: project.ID},
						},
						Value: 0.0,
					}
					votes[rulePath].Value += ruleConfidence
					validVotesCount++
				}
			}

		}
	}
	// [Mitigation 15] Require a minimum number of voters for a decision; disabling the recommendation when too few voters remain
	if validVotesCount < minVoterThreshold {
		slog.Info("not enough valid votes to create a crowdsourced VEX rule", "validVotesCount", validVotesCount)
		return VexRule{}, fmt.Errorf("not enough valid votes to create a crowdsourced VEX rule, validVotesCount: %d", validVotesCount)
	}

	// [Mitigation 31] Use standardized cutoff; test with extreme values; define deterministictie-breaking rules
	maximumValue := 0.0
	crowdsourcedVexRulePath := ""
	for key, value := range votes {
		if value.Value > maximumValue {
			maximumValue = value.Value
			crowdsourcedVexRulePath = key
		}
	}

	// At this point we have a recommendation for a VexRule and want to return the datastructure of the VexRule to the user
	// For that take any fitting VexRule from the database, since they should all be the same
	// Concerns here are:
	// 1. Does it matter which VexRule of which organization we return or is the origin of the VexRule irrelevant since the Rule data is the same?
	// 2. Is it privacy wise correct to return any VexRule, considering that the assetID will link the VexRule to an organization?
	// Thoughts:
	// 1. It should'nt really matter whom's VexRule we recommend as long as the data is correct
	// 2. We can strip out the assetID or only return the relevant data to create a new VexRule with the AssetID of the user who needed the recommendation
	crowdsourcedVexRule, found := findVexRuleFromPath(crowdsourcedVexRulePath, inVexRules)
	if !found {
		slog.Error("failed to find crowdsourced VEX rule", "path", crowdsourcedVexRule)
		return VexRule{}, fmt.Errorf("failed to find crowdsourced VEX rule for path: %s", crowdsourcedVexRulePath)
	}
	return crowdsourcedVexRule, nil
}
