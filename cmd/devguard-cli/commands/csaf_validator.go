package commands

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

type csafRunner struct {
	orgRepository            shared.OrganizationRepository
	assetRepository          shared.AssetRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	csafService              shared.CSAFService
}

func NewCSAFRunner(assetRepository shared.AssetRepository, orgRepository shared.OrganizationRepository, dependencyVulnRepository shared.DependencyVulnRepository, csafService shared.CSAFService) *csafRunner {
	return &csafRunner{
		dependencyVulnRepository: dependencyVulnRepository,
		orgRepository:            orgRepository,
		assetRepository:          assetRepository,
		csafService:              csafService,
	}
}

type csafPath struct {
	OrgName   string
	AssetName string
	Year      int
	CVEID     string
}

func (path csafPath) ToString() string {
	if path.Year != 0 {
		return fmt.Sprintf("%s/%s/%d/%s", path.OrgName, path.AssetName, path.Year, path.CVEID)
	}
	return fmt.Sprintf("%s/%s/%s", path.OrgName, path.AssetName, path.CVEID)
}

type detailedError struct {
	InternalError   error
	IsSemanticError bool
	Description     string
	Path            csafPath
}

type validationJob struct {
	Err    detailedError
	Report *csaf.Advisory
}

type buildingJob struct {
	orgName   string
	assetID   uuid.UUID
	assetSlug string
	cveID     string
}

func NewCSAFValidateCommand() *cobra.Command {
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate all CSAF report",
		Long:  "Iterates over all CSAF reports in all orgs and validates each one syntactically and semantically, and reports any encountered errors with a detailed description",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint

			migrateDB()
			app := fx.New(
				fx.NopLogger,
				database.Module,
				fx.Supply(database.GetPoolConfigFromEnv()),
				repositories.Module,
				services.ServiceModule,
				fx.Provide(NewCSAFRunner),
				fx.Invoke(func(
					runner *csafRunner,
				) error {
					if len(args) == 1 {
						return runner.validationController(&args[0])
					}
					return runner.validationController(nil)
				}),
			)
			if err := app.Start(context.Background()); err != nil {
				return err
			}
			return nil
		},
	}
	return validateCmd
}

type resultCollector struct {
	validationMutex      *sync.Mutex
	CorrectValidations   []detailedError
	IncorrectValidations []detailedError
}

func (collector *resultCollector) addCorrectValidation(validation detailedError) {
	collector.validationMutex.Lock()
	collector.CorrectValidations = append(collector.CorrectValidations, validation)
	collector.validationMutex.Unlock()
}

func (collector *resultCollector) addIncorrectValidation(validation detailedError) {
	collector.validationMutex.Lock()
	collector.IncorrectValidations = append(collector.IncorrectValidations, validation)
	collector.validationMutex.Unlock()
}

var (
	csafValidationBufferSize = 50
	csafBuildingBufferSize   = 500
	csafValidatorAmount      = 1
	csafBuilderAmount        = 7
)

func (runner csafRunner) validationController(outputPath *string) error {
	start := time.Now()

	buildingJobs := make(chan buildingJob, csafBuildingBufferSize)
	validationJobs := make(chan validationJob, csafValidationBufferSize)

	collector := &resultCollector{
		validationMutex: &sync.Mutex{},
	}
	buildingWaitGroup := &sync.WaitGroup{}
	waitGroup := &sync.WaitGroup{}

	waitGroup.Add(1)
	go runner.IterateAssets(buildingJobs, collector, waitGroup)

	for range csafBuilderAmount {
		buildingWaitGroup.Add(1)
		go runner.buildCSAFReports(buildingJobs, validationJobs, collector, buildingWaitGroup)
	}

	// make sure to close channel after all reports are built
	go func() {
		buildingWaitGroup.Wait()
		close(validationJobs)
	}()

	for range csafValidatorAmount {
		waitGroup.Add(1)
		go ValidationWorkerFunction(validationJobs, collector, waitGroup)
	}

	waitGroup.Wait()
	slog.Info("finished checking all csaf reports", "time elapsed", time.Since(start))
	incorrect := collector.CorrectValidations[0]
	incorrect.IsSemanticError = true
	incorrect.Description = "This is not an actual error"

	incorrect2 := collector.CorrectValidations[1]
	incorrect2.InternalError = fmt.Errorf("my custom error")
	incorrect2.Description = "The revision entry numbers under document.tracking.revision_history.number are not properly iterating"

	collector.IncorrectValidations = append(collector.IncorrectValidations, incorrect, incorrect2)
	collector.outputResults(outputPath)
	return nil
}

func (runner csafRunner) buildCSAFReports(buildingJobs chan buildingJob, validateJobs chan validationJob, collector *resultCollector, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	for buildingJob := range buildingJobs {
		errWithDetail := detailedError{Path: csafPath{OrgName: buildingJob.orgName, AssetName: buildingJob.assetSlug, CVEID: buildingJob.cveID}}
		report, err := runner.csafService.GenerateCSAFReport(buildingJob.orgName, buildingJob.assetID, buildingJob.assetSlug, buildingJob.cveID)
		if err != nil {
			collector.addIncorrectValidation(errWithDetail.buildInternalError(err, "could not build CSAF report"))
			continue
		}
		validateJobs <- validationJob{Report: &report, Err: errWithDetail}
	}
}

func (runner csafRunner) IterateAssets(buildingJobs chan buildingJob, collector *resultCollector, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	defer close(buildingJobs)
	orgs, err := runner.orgRepository.All()
	if err != nil {
		collector.addIncorrectValidation(detailedError{}.buildInternalError(err, "could not fetch organizations"))
		return
	}
	for _, org := range orgs {
		assets, err := runner.assetRepository.GetByOrgID(org.ID)
		if err != nil {
			collector.addIncorrectValidation(detailedError{Path: csafPath{OrgName: org.Name}}.buildInternalError(err, "could not fetch assets for organization"))
			continue
		}
		for _, asset := range assets {
			vulns, err := services.GetCSAFVulnsForAsset(asset.ID, runner.dependencyVulnRepository)
			if err != nil {
				collector.addIncorrectValidation(detailedError{Path: csafPath{OrgName: org.Name, AssetName: asset.Slug}}.buildInternalError(err, "could not fetch vulnerabilities for asset"))
				continue
			}
			for _, vuln := range vulns {
				buildingJobs <- buildingJob{orgName: org.Name, assetID: asset.ID, assetSlug: asset.Slug, cveID: vuln.CVEID}
			}
		}
	}
}

func ValidationWorkerFunction(jobs chan validationJob, collector *resultCollector, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	for job := range jobs {
		processJob(job, collector)
	}
}

func processJob(currentJob validationJob, collector *resultCollector) {
	valResult := currentJob.Err
	defer func() {
		if r := recover(); r != nil {
			collector.addIncorrectValidation(valResult.buildInternalError(
				fmt.Errorf("panic: %v", r),
				fmt.Sprintf("ran into panic in path: %s", valResult.Path.ToString()),
			))
			slog.Error("recovered from panic whilst validating csaf report", "path", valResult.Path, "panic", r)
		}
	}()
	report := *currentJob.Report

	// profile tests
	if string(*report.Document.Category) != "csaf_vex" {
		collector.addIncorrectValidation(valResult.buildSemanticError("invalid profile, should be csaf_vex"))
		return
	}

	if report.ProductTree == nil {
		collector.addIncorrectValidation(valResult.buildSemanticError("csaf_vex profile must contain a product tree"))
		return
	}

	if len(report.Vulnerabilities) != 1 {
		collector.addIncorrectValidation(valResult.buildSemanticError("Contradicting amount of vulnerability entries"))
		return
	}

	vulnObject := report.Vulnerabilities[0]
	if len(vulnObject.Notes) == 0 {
		collector.addIncorrectValidation(valResult.buildSemanticError("csaf_vex profile requires notes for each vulnerability object"))
		return
	}

	if vulnObject.ProductStatus == nil {
		collector.addIncorrectValidation(valResult.buildSemanticError("csaf_vex profile requires a product status object inside each vulnerability object"))
		return
	}

	productStatus := *vulnObject.ProductStatus

	if productStatus.UnderInvestigation == nil && productStatus.Fixed == nil && productStatus.KnownAffected == nil && productStatus.KnownNotAffected == nil {
		collector.addIncorrectValidation(valResult.buildSemanticError("csaf_vex profile requires at least one of fixed, known_affected, known_not_affected, or under_investigation to be present in product_status"))
		return
	}

	// check if the id of the document matches the number of revision entries
	documentID, err := strconv.Atoi(string(*report.Document.Tracking.ID))
	if err != nil {
		collector.addIncorrectValidation(valResult.buildInternalError(err, "Could not convert document.tracking.id to a number"))
		return
	}
	revisionEntries := report.Document.Tracking.RevisionHistory
	if documentID != len(revisionEntries) {
		collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("The document id at document.tracking.id does not match the amount of revision entries.\nExpected (id):%d\nActual (len):%d", documentID, len(revisionEntries))))
		return
	}

	// every vuln has at least 1 detection event
	if len(revisionEntries) == 0 {
		collector.addIncorrectValidation(valResult.buildSemanticError("no revision entry was found"))
		return
	}

	if !strings.Contains(strings.ToLower(*revisionEntries[0].Summary), "detected") {
		collector.addIncorrectValidation(valResult.buildSemanticError("first revision entry should be detected entry"))
		return
	}

	// also check against the latest revision entry number
	for i, entry := range revisionEntries {
		lastRevisionEntryID, err := strconv.Atoi(string(*entry.Number))
		if err != nil {
			collector.addIncorrectValidation(valResult.buildInternalError(err, "Could not convert document.tracking.revision_history.number to a number"))
			return
		}
		if i+1 != lastRevisionEntryID {
			collector.addIncorrectValidation(valResult.buildSemanticError("The revision entry numbers under document.tracking.revision_history.number are not properly iterating"))
			return
		}
	}

	// check if the current release time stamp is the same as the latest revision history entry timestamp
	currentRelease, err := time.Parse(time.RFC3339, *report.Document.Tracking.CurrentReleaseDate)
	if err != nil {
		collector.addIncorrectValidation(valResult.buildInternalError(err, "could not parse document.tracking.current_release_date timestamp"))
		return
	}
	lastEntryTimestamp, err := time.Parse(time.RFC3339, *report.Document.Tracking.RevisionHistory[len(report.Document.Tracking.RevisionHistory)-1].Date)
	if err != nil {
		collector.addIncorrectValidation(valResult.buildInternalError(err, "could not parse document.tracking.revision_history.date timestamp"))
		return
	}

	if !currentRelease.Equal(lastEntryTimestamp) {
		collector.addIncorrectValidation(valResult.buildSemanticError("The current release time stamp (document.tracking.current_release_date) does not match the date of the last revision history entry (document.tracking.revision_history.date)"))
		return
	}

	// test productIDs
	// first map all product ids for faster lookup
	productIDs := make(map[string]struct{}, len(*report.ProductTree.FullProductNames))
	for _, product := range *report.ProductTree.FullProductNames {
		productIDs[string(*product.ProductID)] = struct{}{}
	}

	relationships := *report.ProductTree.RelationShips
	// validate productIDs in each relationship entry and track relationship productIDs
	relationshipIDs := make(map[string]struct{}, len(relationships))
	for _, relationship := range relationships {
		relationshipIDs[string(*relationship.FullProductName.ProductID)] = struct{}{}
		_, ok := productIDs[string(*relationship.ProductReference)]
		if !ok {
			collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("product ID %s in product_tree.relationships.product_reference is not defined in product IDs (product_tree.full_product_names.product_id)", *relationship.ProductReference)))
			return
		}
		_, ok = productIDs[string(*relationship.RelatesToProductReference)]
		if !ok {
			collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("product ID %s in product_tree.relationships.relates_to_product_reference is not defined in product IDs (product_tree.full_product_names.product_id)", *relationship.ProductReference)))
			return
		}
	}

	// now after validating the relationships we can append their product IDs to the other product IDs
	maps.Copy(productIDs, relationshipIDs)

	// do the same thing for product status in the vulnerability object
	// first build a combined slice of all products referenced in the vuln object
	allSlices := []csaf.Products{safeDereferenceProducts(productStatus.FirstAffected), safeDereferenceProducts(productStatus.FirstFixed), safeDereferenceProducts(productStatus.Fixed), safeDereferenceProducts(productStatus.KnownAffected), safeDereferenceProducts(productStatus.KnownNotAffected), safeDereferenceProducts(productStatus.LastAffected), safeDereferenceProducts(productStatus.Recommended), safeDereferenceProducts(productStatus.UnderInvestigation)}
	allProductIDsInStates := make([]*csaf.ProductID, 0, len(productIDs))
	for _, slice := range allSlices {
		allProductIDsInStates = append(allProductIDsInStates, slice...)
	}

	for _, productID := range allProductIDsInStates {
		_, ok := productIDs[string(*productID)]
		if !ok {
			collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("product ID %s in vulnerabilities.product_status is not defined in product IDs (product_tree.full_product_names.product_id)", string(*productID))))
			return
		}
	}

	// also check if a product is in present multiple times (in different product statuses)
	// first build logical groups of different product statuses
	contradictoryIDGroups := [][]csaf.Products{{safeDereferenceProducts(productStatus.FirstAffected), safeDereferenceProducts(productStatus.KnownAffected), safeDereferenceProducts(productStatus.LastAffected)}, {safeDereferenceProducts(productStatus.KnownNotAffected)}, {safeDereferenceProducts(productStatus.FirstFixed), safeDereferenceProducts(productStatus.Fixed)}, {safeDereferenceProducts(productStatus.UnderInvestigation)}}

	// for each contradicting group -> iterate through each product status -> iterate through each productID present in that product status:
	// for each other contradicting group -> iterate through each of their product statuses -> iterate through each productID present and check if they are equal
	for i, group := range contradictoryIDGroups {
		// Create a new slice to avoid modifying the original array
		otherIDGroups := make([][]csaf.Products, 0, len(contradictoryIDGroups)-1)
		otherIDGroups = append(otherIDGroups, contradictoryIDGroups[:i]...)
		otherIDGroups = append(otherIDGroups, contradictoryIDGroups[i+1:]...)
		for _, productsInGroup := range group {
			for j, currentProductID := range productsInGroup {
				// for each product check it against each other product in a contradicting group
				for _, productsInOtherGroup := range otherIDGroups {
					for _, otherProducts := range productsInOtherGroup {
						for _, otherProductID := range otherProducts {
							if *otherProductID == *currentProductID {
								collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("productID %s appears multiple times in contradicting vulnerabilities.product_status groups", string(*currentProductID))))
								return
							}
						}
					}
				}

				// also check for duplicate productIDs in the SAME product status
				otherProductsInGroup := make(csaf.Products, 0, len(productsInGroup))
				otherProductsInGroup = append(otherProductsInGroup, productsInGroup[:j]...)
				otherProductsInGroup = append(otherProductsInGroup, productsInGroup[j+1:]...)
				for _, otherProductID := range otherProductsInGroup {
					if *otherProductID == *currentProductID {
						collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("productID %s appears multiple times in the same vulnerabilities.product_status group", string(*currentProductID))))
						return
					}
				}
			}
		}
	}

	// check if product IDs in remediations are properly defined in product tree
	for _, remediation := range vulnObject.Remediations {
		if remediation.ProductIds == nil {
			collector.addIncorrectValidation(valResult.buildSemanticError("no products found in remediation (vulnerabilities.remediations.product_ids)"))
			return
		}
		for _, productID := range *remediation.ProductIds {
			_, ok := productIDs[string(*productID)]
			if !ok {
				collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("product ID %s in vulnerabilities.remediations.product_ids is not defined in product IDs (product_tree.full_product_names.product_id)", string(*productID))))
				return
			}
		}
	}

	// test if the revision history entries are sorted asc by timestamp
	previousTimestamp, err := time.Parse(time.RFC3339, *revisionEntries[0].Date)
	if err != nil {
		collector.addIncorrectValidation(valResult.buildInternalError(err, "could not parse 1. timestamp from document.tracking.revision_history.date"))
		return
	}
	for i, entry := range revisionEntries[1:] {
		currentTimestamp, err := time.Parse(time.RFC3339, *entry.Date)
		if err != nil {
			collector.addIncorrectValidation(valResult.buildInternalError(err, fmt.Sprintf("could not parse %d. timestamp from document.tracking.revision_history.date", i+2)))
			return
		}
		if currentTimestamp.Before(previousTimestamp) {
			collector.addIncorrectValidation(valResult.buildSemanticError(fmt.Sprintf("%d. revision history entry timestamp (document.tracking.revision_history.date) is not after the previous timestamp", i+2)))
			return
		}
		previousTimestamp = currentTimestamp
	}
	collector.addCorrectValidation(valResult)
}

func safeDereferenceProducts(products *csaf.Products) csaf.Products {
	if products == nil {
		return csaf.Products{}
	}
	return *products
}

func (detErr detailedError) buildSemanticError(description string) detailedError {
	detErr.IsSemanticError = true
	detErr.Description = description
	return detErr
}

func (detErr detailedError) buildInternalError(err error, description string) detailedError {
	detErr.InternalError = err
	detErr.Description = description
	return detErr
}

func (collector resultCollector) outputResults(outputPath *string) {
	type templateData struct {
		resultCollector
		Timestamp                      string
		Total                          int
		AmountCorrectClassifications   int
		AmountIncorrectClassifications int
	}

	data := templateData{
		resultCollector:                collector,
		Timestamp:                      time.Now().Format(time.RFC3339),
		Total:                          len(collector.CorrectValidations) + len(collector.IncorrectValidations),
		AmountCorrectClassifications:   len(collector.CorrectValidations),
		AmountIncorrectClassifications: len(collector.IncorrectValidations),
	}

	tmpl, err := template.New("output").Parse(`
----------------------------CSAF VALIDATOR OUTPUT----------------------------

Date: 				{{.Timestamp}}
Total reports processed: 	{{.Total}}
Successful validations: 	{{.AmountCorrectClassifications}}
Unsuccessful validations: 	{{.AmountIncorrectClassifications}}
{{if eq .AmountIncorrectClassifications 0}}
All reports are valid.{{else}}
-------------------------------Error Summaries--------------------------------
{{range .IncorrectValidations}}

Error-Type:			{{if .IsSemanticError}}Semantic Error{{else}}Internal Error{{end}}
Path: 	 			{{.Path.ToString}}
Summary:			{{.Description}}
{{if .InternalError}}
Internal-Error: 		{{.InternalError}}{{end}}

##############################################################################{{end}}{{end}}
--------------------------END-CSAF VALIDATOR OUTPUT--------------------------`)
	if err != nil {
		slog.Error("could not parse template", "err", err)
		return
	}
	var summary strings.Builder
	err = tmpl.Execute(&summary, data)
	if err != nil {
		slog.Error("could not format validation data", "err", err)
	}
	if outputPath == nil {
		slog.Info(summary.String())
	} else {
		fd, err := os.Create(*outputPath)
		if err != nil {
			slog.Error("could not create file for output")
			return
		}
		defer fd.Close()
		_, err = fd.WriteString(summary.String())
		if err != nil {
			slog.Error("could not write output to file", "err", err)
		}
	}
}
