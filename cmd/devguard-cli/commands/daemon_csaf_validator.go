package commands

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
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

func (path csafPath) toString() string {
	if path.Year != 0 {
		return fmt.Sprintf("%s/%s/%d/%s", path.OrgName, path.AssetName, path.Year, path.CVEID)
	}
	return fmt.Sprintf("%s/%s/%s", path.OrgName, path.AssetName, path.CVEID)
}

type detailedError struct {
	InternalError error
	SemanticError bool
	Description   string
	Path          csafPath
}

type job struct {
	Err    detailedError
	Report *csaf.Advisory
}

func NewCSAFValidateCommand() *cobra.Command {
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "TODO",
		Long:  "TODO",
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
					return runner.IterateAssets()
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

func (runner csafRunner) IterateAssets() error {
	orgs, err := runner.orgRepository.All()
	if err != nil {
		return err
	}
	slog.Info("orgs found", "amount", len(orgs))
	for _, org := range orgs {
		assets, err := runner.assetRepository.GetByOrgID(org.ID)
		if err != nil {
			return err
		}
		for _, asset := range assets {
			vulns, err := services.GetCSAFVulnsForAsset(asset.ID, runner.dependencyVulnRepository)
			if err != nil {
				return err
			}
			for _, vuln := range vulns {
				slog.Info("start building report", "cve", vuln.CVEID)
				report, err := runner.csafService.GenerateCSAFReport(org, asset, vuln.CVEID)
				if err != nil {
					return err
				}
				slog.Info("successfully built csaf report, start validating")

				errWithDetail := detailedError{Path: csafPath{OrgName: org.Slug, AssetName: asset.Slug, CVEID: vuln.CVEID}}
				errWithDetail = ValidateReport(job{Report: &report, Err: errWithDetail})
				if errWithDetail.InternalError != nil {
					slog.Error("ran into internal error", "path", errWithDetail.Path.toString(), "err", errWithDetail.InternalError)
				} else if errWithDetail.SemanticError {
					slog.Error("ran into semantic error", "path", errWithDetail.Path.toString(), "description", errWithDetail.Description)
				} else {
					slog.Info("successfully validated report", "path", errWithDetail.Path.toString())
				}
			}

		}
	}
	return nil
}

func ValidateReport(job job) (resultErr detailedError) {
	valResult := job.Err
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered from panic whilst validating csaf report", "path", valResult.Path)
			resultErr = valResult
			resultErr.InternalError = fmt.Errorf("panic")
		}
	}()

	report := *job.Report

	// profile tests
	if string(*report.Document.Category) != "csaf_vex" {
		return valResult.buildSemanticError("invalid profile, should be csaf_vex")
	}

	if report.ProductTree == nil {
		return valResult.buildSemanticError("csaf_vex profile must contain a product tree")
	}

	if len(report.Vulnerabilities) != 1 {
		return valResult.buildSemanticError("Contradicting amount of vulnerability entries")
	}

	vulnObject := report.Vulnerabilities[0]
	if len(vulnObject.Notes) == 0 {
		return valResult.buildSemanticError("csaf_vex profile requires notes for each vulnerability object")
	}

	if vulnObject.ProductStatus == nil {
		return valResult.buildSemanticError("csaf_vex profile requires a product status object inside each vulnerability object")
	}

	productStatus := *vulnObject.ProductStatus

	if productStatus.UnderInvestigation == nil && productStatus.Fixed == nil && productStatus.KnownAffected == nil && productStatus.KnownNotAffected == nil {
		return valResult.buildSemanticError("csaf_vex profile requires at least one of fixed, known_affected, known_not_affected, or under_investigation to be present in product_status")
	}

	// check if the id of the document matches the number of revision entries
	documentID, err := strconv.Atoi(string(*report.Document.Tracking.ID))
	if err != nil {
		return valResult.buildInternalError(err, "Could not convert document.tracking.id to a number")
	}
	revisionEntries := report.Document.Tracking.RevisionHistory
	if documentID != len(revisionEntries) {
		return valResult.buildSemanticError(fmt.Sprintf("The document id at document.tracking.id does not match the amount of revision entries.\nExpected (id):%d\nActual (len):%d", documentID, len(revisionEntries)))
	}

	// every vuln has at least 1 detection event
	if len(revisionEntries) == 0 {
		return valResult.buildSemanticError("no revision entry was found")
	}

	if !strings.Contains(strings.ToLower(*revisionEntries[0].Summary), "detected") {
		return valResult.buildSemanticError("first revision entry should be detected entry")
	}

	// also check against the latest revision entry number
	for i, entry := range revisionEntries {
		lastRevisionEntryID, err := strconv.Atoi(string(*entry.Number))
		if err != nil {
			return valResult.buildInternalError(err, "Could not convert document.tracking.revision_history.number to a number")
		}
		if i+1 != lastRevisionEntryID {
			return valResult.buildSemanticError("The revision entry numbers under document.tracking.revision_history.number are not properly iterating")
		}
	}

	// check if the current release time stamp is the same as the latest revision history entry timestamp
	currentRelease, err := time.Parse(time.RFC3339, *report.Document.Tracking.CurrentReleaseDate)
	if err != nil {
		return valResult.buildInternalError(err, "could not parse document.tracking.current_release_date timestamp")
	}
	lastEntryTimestamp, err := time.Parse(time.RFC3339, *report.Document.Tracking.RevisionHistory[len(report.Document.Tracking.RevisionHistory)-1].Date)
	if err != nil {
		return valResult.buildInternalError(err, "could not parse document.tracking.revision_history.date timestamp")
	}

	if !currentRelease.Equal(lastEntryTimestamp) {
		return valResult.buildSemanticError("The current release time stamp (document.tracking.current_release_date) does not match the date of the last revision history entry (document.tracking.revision_history.date)")
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
			return valResult.buildSemanticError(fmt.Sprintf("product ID %s in product_tree.relationships.product_reference is not defined in product IDs (product_tree.full_product_names.product_id)", *relationship.ProductReference))
		}
		_, ok = productIDs[string(*relationship.RelatesToProductReference)]
		if !ok {
			return valResult.buildSemanticError(fmt.Sprintf("product ID %s in product_tree.relationships.relates_to_product_reference is not defined in product IDs (product_tree.full_product_names.product_id)", *relationship.ProductReference))
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
			return valResult.buildSemanticError(fmt.Sprintf("product ID %s in vulnerabilities.product_status is not defined in product IDs (product_tree.full_product_names.product_id)", string(*productID)))
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
								return valResult.buildSemanticError(fmt.Sprintf("productID %s appears multiple times in contradicting vulnerabilities.product_status groups", string(*currentProductID)))
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
						return valResult.buildSemanticError(fmt.Sprintf("productID %s appears multiple times in the same vulnerabilities.product_status group", string(*currentProductID)))
					}
				}
			}
		}
	}

	// check if product IDs in remediations are properly defined in product tree
	for _, remediation := range vulnObject.Remediations {
		for _, productID := range *remediation.ProductIds {
			_, ok := productIDs[string(*productID)]
			if !ok {
				return valResult.buildSemanticError(fmt.Sprintf("product ID %s in vulnerabilities.remediations.product_ids is not defined in product IDs (product_tree.full_product_names.product_id)", string(*productID)))
			}
		}
	}

	// test if the revision history entries are sorted asc by timestamp
	previousTimestamp, err := time.Parse(time.RFC3339, *revisionEntries[0].Date)
	if err != nil {
		return valResult.buildInternalError(err, "could not parse 1. timestamp from document.tracking.revision_history.date")
	}
	for i, entry := range revisionEntries[1:] {
		currentTimestamp, err := time.Parse(time.RFC3339, *entry.Date)
		if err != nil {
			return valResult.buildInternalError(err, fmt.Sprintf("could not parse %d. timestamp from document.tracking.revision_history.date", i+2))
		}
		if currentTimestamp.Before(previousTimestamp) {
			return valResult.buildSemanticError(fmt.Sprintf("%d. revision history entry timestamp (document.tracking.revision_history.date) is not after the previous timestamp", i+2))
		}
	}

	return valResult
}

func safeDereferenceProducts(products *csaf.Products) csaf.Products {
	if products == nil {
		return csaf.Products{}
	}
	return *products
}

func (detErr detailedError) buildSemanticError(description string) detailedError {
	detErr.SemanticError = true
	detErr.Description = description
	return detErr
}

func (detErr detailedError) buildInternalError(err error, description string) detailedError {
	detErr.InternalError = err
	detErr.Description = description
	return detErr
}
