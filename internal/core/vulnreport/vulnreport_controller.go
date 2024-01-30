package vulnreport

import (
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/asset"

	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/labstack/echo/v4"
	"github.com/owenrumney/go-sarif/sarif"
)

type VulnReportHttpController struct {
	flawRepository flaw.Repository
	flawEnricher   flaw.Enricher

	flawEventRepository flaw.EventRepository

	assetRepository asset.Repository
}

func NewHttpController(
	flawRepository flaw.Repository,
	flawEnricher flaw.Enricher,
	flawEventRepository flaw.EventRepository,
	assetRepository asset.Repository,
) VulnReportHttpController {
	return VulnReportHttpController{
		flawRepository: flawRepository,
		flawEnricher:   flawEnricher,

		flawEventRepository: flawEventRepository,
		assetRepository:     assetRepository,
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
	for _, result := range tmpResults[:1] {
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

func parseReport(ctx core.Context) (rulesAndResults, error) {
	// read the request body
	reader := http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, 1024*1024*10) // 10MB

	bytes, err := io.ReadAll(reader)
	if err != nil {
		return rulesAndResults{}, echo.NewHTTPError(400, "unable to read request body").WithInternal(err)
	}
	report, err := sarif.FromBytes(bytes)
	if err != nil {
		return rulesAndResults{}, echo.NewHTTPError(400, "unable to parse SARIF report").WithInternal(err)
	}

	return getRulesAndResults(report)
}

func (c VulnReportHttpController) ImportVulnReport(ctx core.Context) error {
	assetID := ctx.Param("assetID")
	if assetID == "" {
		return echo.NewHTTPError(400, "no assetID provided")
	}

	assetUUID := uuid.MustParse(assetID)
	userUUID := uuid.MustParse(core.GetSession(ctx).GetUserID())

	// parse the report
	rulesAndResults, err := parseReport(ctx)
	if err != nil {
		return err
	}

	// get the current flaws.
	// we will use this to determine if a flaw is new or not
	flaws, err := c.flawRepository.GetByAssetId(nil, assetUUID)

	if err != nil {
		return echo.NewHTTPError(500, "unable to get flaws").WithInternal(err)
	}

	// split the flaws into fixed and unfixed
	// key is the rule id
	fixedFlaws := map[string]flaw.Model{}
	unfixedFlaws := map[string]flaw.Model{}

	for _, f := range flaws {
		if f.State == flaw.StateFixed {
			fixedFlaws[f.RuleID] = f
		} else {
			unfixedFlaws[f.RuleID] = f
		}
	}

	newDetectedFlaws := []flaw.Model{}
	newFlawEvents := []flaw.EventModel{}
	flawsToUpdate := []flaw.Model{}

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
		if f, ok := fixedFlaws[*result.RuleID]; ok {
			// we need to create a new detected event.
			flawEvent := flaw.EventModel{
				Type:   flaw.EventTypeDetected,
				FlawID: f.ID,
				UserID: userUUID,
			}
			newFlawEvents = append(newFlawEvents, flawEvent)

			// we need to reopen the flaw
			flawsToUpdate = append(flawsToUpdate, flawEvent.Apply(f))

			continue
		}

		// we never saw this flaw before
		newDetectedFlaws = append(newDetectedFlaws, flaw.Model{
			RuleID:  *result.RuleID,
			Message: result.Message.Text,
			AssetID: assetUUID,
			State:   flaw.StateOpen,
			Events: []flaw.EventModel{
				{
					Type:   flaw.EventTypeDetected,
					UserID: userUUID,
				},
			},
		})
	}

	// now save all.
	err = c.flawRepository.Transaction(func(tx core.DB) error {
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

		if len(flawsToUpdate) > 0 {
			return c.flawRepository.UpdateBatch(tx, flawsToUpdate)
		}

		return nil
	})

	// enrich the flaws
	// this method runs asynchronously
	c.flawEnricher.AsyncEnrich(newDetectedFlaws)

	if err != nil {
		return echo.NewHTTPError(500, "unable to create new flaws").WithInternal(err)
	}

	return ctx.JSON(200, nil)
}
