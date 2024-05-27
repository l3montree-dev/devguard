package vulndb

import (
	"log/slog"
	"strings"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/obj"
	"github.com/labstack/echo/v4"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type repository interface {
	FindAllListPaged(tx database.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.CVE], error)
	FindCVE(tx database.DB, cveId string) (any, error)
}

type cveHttpController struct {
	cveRepository repository
}

func NewHttpController(cveRepository repository) *cveHttpController {
	return &cveHttpController{
		cveRepository: cveRepository,
	}
}

func (c cveHttpController) ListPaged(ctx core.Context) error {

	pagedResp, err := c.cveRepository.FindAllListPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	env := core.GetEnvironmental(ctx)

	if env.AvailabilityRequirements != "" || env.ConfidentialityRequirements != "" || env.IntegrityRequirements != "" {

		for i, cve := range pagedResp.Data {
			risk, vector := riskCalculation(cve, env)

			pagedResp.Data[i].Vector = vector
			pagedResp.Data[i].Risk = risk

		}
	}

	return ctx.JSON(200, pagedResp)
}

func (c cveHttpController) Read(ctx core.Context) error {
	pagedResp, err := c.cveRepository.FindCVE(
		nil,
		core.GetParam(ctx, "cveId"),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}
	cve := pagedResp.(models.CVE)

	e := core.GetEnvironmental(ctx)

	risk, vector := riskCalculation(cve, e)
	cve.Risk = risk
	cve.Vector = vector

	return ctx.JSON(200, cve)
}

func riskCalculation(cve models.CVE, env core.Environmental) (obj.RiskMetrics, string) {
	risk := obj.RiskMetrics{
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
			return obj.RiskMetrics{}, vector
		}
		// build up the temporal score
		// if all affected components have a fixed version, we set it to official fix
		if len(cve.AffectedComponents) > 0 {
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
		}

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
			return obj.RiskMetrics{}, vector
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

		environmentalScore := cvss.Score()
		cvss.Set("E", oldE) // nolint:errcheck
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
			slog.Warn("Error parsing CVSS vector", "vector", vector, "error", err)
			return obj.RiskMetrics{}, vector
		}
		cvss.Set("RL", "ND") // nolint:errcheck

		if len(cve.AffectedComponents) > 0 {
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
		}

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
		if env != (core.Environmental{}) {
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

func setEnv(cvss cvssInterface, env core.Environmental) {
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
