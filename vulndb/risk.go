package vulndb

import (
	"log/slog"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/l3montree-dev/devguard/utils"
)

func RawRisk(cve models.CVE, env shared.Environmental, affectedComponentDepth int) dtos.RiskCalculationReport {
	if affectedComponentDepth == 0 {
		affectedComponentDepth = 1
	}
	e := shared.SanitizeEnv(env)
	r, vector := RiskCalculation(cve, e)
	risk := r.WithEnvironmentAndThreatIntelligence
	one := float64(1)
	epss := float64(utils.OrDefault(cve.EPSS, 0))
	tmp := risk * (epss + one)
	// return the risk with 2 decimal places
	tmp = float64(int(tmp*100)) / 100
	// the risk might be in the range of 0.0 to 20.0
	// crop that down to 0.0 to 10.0
	tmp = tmp / 2
	// use the affectedComponent depth to further decrease the risk, if its deep inside the dependency tree
	tmp = tmp / float64(affectedComponentDepth)
	// round to 2 decimal places
	tmp = float64(int(tmp*100)) / 100

	return dtos.RiskCalculationReport{
		Risk: tmp,

		EPSS:      utils.OrDefault(cve.EPSS, 0),
		BaseScore: float64(cve.CVSS),

		UnderAttack:   cve.CISAActionDue != nil,
		ExploitExists: len(cve.Exploits) > 0,
		VerifiedExploitExists: utils.Any(
			cve.Exploits,
			func(e models.Exploit) bool {
				return e.Verified
			},
		),

		ConfidentialityRequirement: e.ConfidentialityRequirements,
		IntegrityRequirement:       e.IntegrityRequirements,
		AvailabilityRequirement:    e.AvailabilityRequirements,

		Vector: vector,
	}
}

func RiskCalculation(cve models.CVE, env shared.Environmental) (dtos.RiskMetrics, string) {
	if cve.Vector == "" {
		return dtos.RiskMetrics{}, ""
	}

	risk := dtos.RiskMetrics{
		BaseScore: float64(cve.CVSS),
	}
	/*
	   //Base Metrics
	   AV : Attack Vector
	   AC : Attack Complexity
	   PR : Privileges Required
	   UI : User Interaction
	   S : Scope
	   C : Confidentiality Impact
	   I : Integrity Impact
	   A : Availability Impact

	   //Environmental (Security Requirements)
	   CR : Confidentiality Requirements
	   IR : Integrity Requirements
	   AR : Availability Requirements

	   //Threat Metrics
	   E : Exploit Maturity
	*/
	/*
		AV := cve.AttackVector
		AC := cve.AttackComplexity
		// AT : AttackRequirements
		PR := cve.PrivilegesRequired
		UI := cve.UserInteraction
		S := cve.Scope
		C := cve.ConfidentialityImpact
		I := cve.IntegrityImpact
		A := cve.AvailabilityImpact

		//Environmental (Security Requirements)
		CR := env.ConfidentialityRequirements
		IR := env.IntegrityRequirements
		AR := env.AvailabilityRequirements

		//Threat Metrics
		E := env.ExploitMaturity
	*/

	vector := cve.Vector
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0") || strings.HasPrefix(vector, "CVSS:3.1"):
		var cvss cvssInterface
		var err error
		if strings.HasPrefix(vector, "CVSS:3.0") {
			cvss, err = gocvss30.ParseVector(vector)
		} else {
			cvss, err = gocvss31.ParseVector(vector)
		}
		if err != nil {
			slog.Warn("Error parsing CVSS vector", "vector", vector, "error", err)
			return dtos.RiskMetrics{}, vector
		}
		// build up the temporal score
		// if all affected components have a fixed version, we set it to official fix

		/**
		Currently this is disabled.
		It does not make any sense, to reduce the risk score, if the affected components have an official fix available.
		Actually those components should be updated to the fixed version first. Low hanging fruits.
		/*if len(cve.AffectedComponents) > 0 {
			officialFix := true
			for _, component := range cve.AffectedComponents {
				if component.SemverFixed == nil {
					officialFix = false
					break
				}
			}
			if officialFix {
				cvss.Set("RL", "O") // nolint:errcheck
			} else {
				cvss.Set("RL", "U") // nolint:errcheck
			}
		}*/

		cvss.Set("E", "U")  // nolint:errcheck
		cvss.Set("RC", "C") // nolint:errcheck
		// check if exploit exist
		if len(cve.Exploits) > 0 {
			// check if there is a verified exploit
			cvss.Set("E", "P") // nolint:errcheck
			for _, exploit := range cve.Exploits {
				if exploit.Verified {
					cvss.Set("E", "F") // nolint:errcheck
					break
				}
			}
		}
		setEnv(cvss, env)
		vector = cvss.Vector()
		risk.WithEnvironment = getBaseAndEnvironmentalScore(cvss, "CVSS:3.0")
		risk.WithThreatIntelligence = getBaseAndThreatIntelligenceScore(cvss, "CVSS:3.0")
		risk.WithEnvironmentAndThreatIntelligence = cvss.EnvironmentalScore()

		return risk, vector
	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			slog.Warn("Error parsing CVSS vector", "vector", vector, "error", err)
			return dtos.RiskMetrics{}, vector
		}
		cvss.Set("E", "U") // nolint:errcheck
		if len(cve.Exploits) > 0 {
			cvss.Set("E", "P") // nolint:errcheck
		}
		if cve.CISAActionDue != nil {
			cvss.Set("E", "A") // nolint:errcheck
		}

		temporalScore := cvss.Score()

		// reset the temporal score again to calculate the environmental score
		oldE, _ := cvss.Get("E")
		cvss.Set("E", "X") // nolint:errcheck
		// set the env manually
		if env.ConfidentialityRequirements != "" {
			cvss.Set("CR", env.ConfidentialityRequirements) // nolint:errcheck
		}
		if env.IntegrityRequirements != "" {
			cvss.Set("IR", env.IntegrityRequirements) // nolint:errcheck
		}
		if env.AvailabilityRequirements != "" {
			cvss.Set("AR", env.AvailabilityRequirements) // nolint:errcheck
		}
		environmentalScore := cvss.Score()
		cvss.Set("E", oldE) // nolint:errcheck

		vector = cvss.Vector()
		risk.BaseScore = float64(cve.CVSS)
		risk.WithEnvironment = environmentalScore
		risk.WithThreatIntelligence = temporalScore
		risk.WithEnvironmentAndThreatIntelligence = cvss.Score()

		return risk, vector

	default:
		//vector = "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:U/RL:ND/RC:C"

		// Should be CVSS v2.0 or is invalid
		// build up the temporal score
		// if all affected components have a fixed version, we set it to official fix
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			slog.Warn("Error parsing CVSS vector", "vector", vector, "error", err, "cve", cve.CVE)
			return dtos.RiskMetrics{}, vector
		}
		// cvss.Set("RL", "ND") // nolint:errcheck

		/*if len(cve.AffectedComponents) > 0 {
			officialFix := true
			for _, component := range cve.AffectedComponents {
				if component.SemverFixed == nil {
					officialFix = false
					break
				}
			}
			if officialFix {
				cvss.Set("RL", "OF") // nolint:errcheck
			} else {
				cvss.Set("RL", "U") // nolint:errcheck
			}
		}*/

		cvss.Set("RC", "C") // nolint:errcheck
		cvss.Set("E", "U")  // nolint:errcheck

		// check if exploit exist
		if len(cve.Exploits) > 0 {
			cvss.Set("E", "POC") // nolint:errcheck

			for _, exploit := range cve.Exploits {
				if exploit.Verified {
					cvss.Set("E", "F") // nolint:errcheck
					break
				}
			}
		}

		setEnv(cvss, env)
		if env != (shared.Environmental{}) {
			risk.WithEnvironmentAndThreatIntelligence = cvss.EnvironmentalScore()
		} else {
			risk.WithEnvironmentAndThreatIntelligence = cvss.TemporalScore()
		}
		risk.WithEnvironment = getBaseAndEnvironmentalScore(cvss, "CVSS:2.0")
		risk.WithThreatIntelligence = getBaseAndThreatIntelligenceScore(cvss, "CVSS:2.0")
		return risk, cvss.Vector()
	}
}

type cvssInterface interface {
	Set(key, value string) error
	Get(key string) (string, error)
	EnvironmentalScore() float64
	TemporalScore() float64
	Vector() string
}

var undefinedMarker map[string]string = map[string]string{
	"CVSS:3.0": "X",
	"CVSS:2.0": "ND",
}

func getBaseAndThreatIntelligenceScore(cvss cvssInterface, version string) float64 {
	// reset the env variables
	oldCR, _ := cvss.Get("CR")
	oldIR, _ := cvss.Get("IR")
	oldAR, _ := cvss.Get("AR")

	cvss.Set("CR", undefinedMarker[version]) // nolint:errcheck
	cvss.Set("IR", undefinedMarker[version]) // nolint:errcheck
	cvss.Set("AR", undefinedMarker[version]) // nolint:errcheck

	score := cvss.TemporalScore()

	// reset the env variables
	cvss.Set("CR", oldCR) // nolint:errcheck
	cvss.Set("IR", oldIR) // nolint:errcheck
	cvss.Set("AR", oldAR) // nolint:errcheck

	return score
}

func getBaseAndEnvironmentalScore(cvss cvssInterface, version string) float64 {
	// reset the threat metrics
	oldE, _ := cvss.Get("E")
	oldRL, _ := cvss.Get("RL")
	oldRC, _ := cvss.Get("RC")

	cvss.Set("E", undefinedMarker[version])  // nolint:errcheck
	cvss.Set("RL", undefinedMarker[version]) // nolint:errcheck
	cvss.Set("RC", undefinedMarker[version]) // nolint:errcheck

	score := cvss.EnvironmentalScore()

	// reset the threat metrics
	cvss.Set("E", oldE)   // nolint:errcheck
	cvss.Set("RL", oldRL) // nolint:errcheck
	cvss.Set("RC", oldRC) // nolint:errcheck

	return score
}

func setEnv(cvss cvssInterface, env shared.Environmental) {
	if env.ConfidentialityRequirements != "" {
		cvss.Set("CR", env.ConfidentialityRequirements) // nolint:errcheck
	}
	if env.IntegrityRequirements != "" {
		cvss.Set("IR", env.IntegrityRequirements) // nolint:errcheck
	}
	if env.AvailabilityRequirements != "" {
		cvss.Set("AR", env.AvailabilityRequirements) // nolint:errcheck
	}
}
