package vulndb

import (
	"fmt"
	"log"
	"strings"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
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

	if env.AvailabilityRequirements != "" || env.ConfidentialityRequirements != "" || env.IntegrityRequirements != "" || env.ExploitMaturity != "" {

		for i, cve := range pagedResp.Data {
			risk := riskCalculation(cve, env)

			cve.Risk = risk

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

	return ctx.JSON(200, pagedResp)
}

func riskCalculation(cve models.CVE, env core.Environmental) int {
	risk := 5
	/*
	   availabilityRequirements := env.AvailabilityRequirements
	   confidentialityRequirements := env.ConfidentialityRequirements
	   integrityRequirements := env.IntegrityRequirements
	   exploitMaturity := env.ExploitMaturity
	*/

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
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L"

	switch {
	default: // Should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			log.Fatal(err)
		}
		_ = cvss
	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			log.Fatal(err)
		}
		_ = cvss

	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			log.Fatal(err)
		}
		_ = cvss

	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			log.Fatal(err)
		}
		_ = cvss
		s := cvss.Score()
		fmt.Printf("%.1f\n", s)

	}

	/*
	   baseScore := c.BaseScore()
	   rat, err := c.Rating(baseScore)
	   if err != nil {
	       log.Fatal(err)
	   }
	   fmt.Printf("%.1f %s\n", baseScore, rat)
	*/
	return risk
}
