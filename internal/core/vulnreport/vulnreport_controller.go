package vulnreport

import (
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/application"
	"github.com/l3montree-dev/flawfix/internal/core/env"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
	"github.com/labstack/echo/v4"
	"github.com/owenrumney/go-sarif/sarif"
)

type VulnReportHttpController struct {
	applicationRepository application.Repository
	flawRepository        flaw.Repository
	flawEventRepository   flawevent.Repository
	envRepository         env.Repository
}

func NewHttpController(
	applicationRepository application.Repository,
	flawRepository flaw.Repository,
	flawEventRepository flawevent.Repository,
	envRepository env.Repository,
) VulnReportHttpController {
	return VulnReportHttpController{
		applicationRepository: applicationRepository,
		flawRepository:        flawRepository,
		flawEventRepository:   flawEventRepository,
		envRepository:         envRepository,
	}
}

type rulesAndResults struct {
	results map[string]*sarif.Result
	rules   map[string]*sarif.ReportingDescriptor
}

func getRulesAndResults(report *sarif.Report) (rulesAndResults, error) {
	tmpResults := []*sarif.Result{}
	tmpRules := []*sarif.ReportingDescriptor{}

	// merge all runs together
	for _, run := range report.Runs {
		tmpResults = append(tmpResults, run.Results...)
		tmpRules = append(tmpRules, run.Tool.Driver.Rules...)
	}

	// remove all rules that are not used
	res := rulesAndResults{
		results: map[string]*sarif.Result{},
		rules:   map[string]*sarif.ReportingDescriptor{},
	}
outer:
	for _, result := range tmpResults {
		if result.RuleID == nil {
			continue
		}

		res.results[*result.RuleID] = result
		for _, rule := range tmpRules {
			if rule.ID == *result.RuleID {
				res.rules[*result.RuleID] = rule
				continue outer
			}
		}

		// we did not find the rule - this should not happen
		// otherwise continue outer should have been called
		return rulesAndResults{}, echo.NewHTTPError(400, "unable to find rule for result")
	}

	return res, nil
}

func (c VulnReportHttpController) ImportVulnReport(ctx core.Context) error {
	envID := ctx.Param("envID")
	if envID == "" {
		return echo.NewHTTPError(400, "no envID provided")
	}

	envUUID := uuid.MustParse(envID)
	userUUID := uuid.MustParse(core.GetSession(ctx).GetUserID())

	// read the request body
	reader := http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, 1024*1024*10) // 10MB

	bytes, err := io.ReadAll(reader)
	if err != nil {
		return echo.NewHTTPError(400, "unable to read request body").WithInternal(err)
	}
	report, err := sarif.FromBytes(bytes)
	if err != nil {
		return echo.NewHTTPError(400, "unable to parse SARIF report").WithInternal(err)
	}

	rulesAndResults, err := getRulesAndResults(report)
	if err != nil {
		return err
	}

	// get the current unfixed flaws.
	// we will use this to determine if a flaw is new or not
	flaws, err := c.flawRepository.GetWithLastEvent(nil, envUUID)

	if err != nil {
		return echo.NewHTTPError(500, "unable to get flaws").WithInternal(err)
	}

	// split the flaws into fixed and unfixed
	// key is the rule id
	fixedFlaws := map[string]flaw.ModelWithLastEvent{}
	unfixedFlaws := map[string]flaw.ModelWithLastEvent{}

	for _, flaw := range flaws {
		if flaw.LastEvent.Type == flawevent.EventTypeFixed {
			fixedFlaws[flaw.RuleID] = flaw
		} else {
			unfixedFlaws[flaw.RuleID] = flaw
		}
	}

	newDetectedFlaws := []flaw.Model{}
	newFlawEvents := []flawevent.Model{}

	// check which flaws needs to be created and which are fixed now.
	// we will do this by comparing the results in the report with the unfixed flaws
	// if a flaw is not in the report, it is fixed
	// if a flaw is in the report, it is not fixed
	for ruleId, result := range rulesAndResults.results {
		// check if it an existing flaw
		if _, ok := unfixedFlaws[ruleId]; ok {
			fmt.Println("flaw is not fixed", ruleId)
			// flaw is not fixed
			// nothing todo here.
			continue
		}
		if flaw, ok := fixedFlaws[*result.RuleID]; ok {
			fmt.Println("flaw is fixed", ruleId)
			// we need to create a new detected event.
			newFlawEvents = append(newFlawEvents, flawevent.Model{
				Type:   flawevent.EventTypeDetected,
				FlawID: flaw.ID,
				UserID: userUUID,
			})
			continue
		}

		fmt.Println("flaw is new", ruleId)

		// we never saw this flaw before
		newDetectedFlaws = append(newDetectedFlaws, flaw.Model{
			RuleID:  *result.RuleID,
			Level:   result.Level,
			Message: result.Message.Text,
			EnvID:   envUUID,
			Events: []flawevent.Model{
				{
					Type:   flawevent.EventTypeDetected,
					UserID: userUUID,
				},
			},
		})
	}

	// now safe all.
	err = c.flawRepository.Transaction(func(tx core.DB) error {
		c.envRepository.UpdateLastReportTime(tx, envUUID)
		// create the new flaws
		if len(newDetectedFlaws) > 0 {
			err := c.flawRepository.CreateBatch(tx, newDetectedFlaws)
			if err != nil {
				return err
			}
		}

		if len(newFlawEvents) > 0 {
			return c.flawEventRepository.CreateBatch(tx, newFlawEvents)
		}

		return nil
	})

	if err != nil {
		return echo.NewHTTPError(500, "unable to create new flaws").WithInternal(err)
	}

	return ctx.JSON(200, flaws)
}
