package integrations

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
)

// batches multiple third party integrations
type thirdPartyIntegrations struct {
	integrations []core.ThirdPartyIntegration
}

var _ core.IntegrationAggregate = &thirdPartyIntegrations{}

func (t *thirdPartyIntegrations) GetIntegration(id core.IntegrationID) core.ThirdPartyIntegration {
	for _, i := range t.integrations {
		if i.GetID() == id {
			return i
		}
	}
	return nil
}

func (t *thirdPartyIntegrations) GetID() core.IntegrationID {
	return core.AggregateID
}

func (t *thirdPartyIntegrations) IntegrationEnabled(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.IntegrationEnabled(ctx)
	})
}

func (t *thirdPartyIntegrations) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	wg := utils.ErrGroup[[]core.Repository](-1)

	for _, i := range t.integrations {
		if i.IntegrationEnabled(ctx) {
			wg.Go(func() ([]core.Repository, error) {
				repos, err := i.ListRepositories(ctx)
				if err != nil {
					slog.Error("error while listing repositories", "err", err)
					// swallow error
					return nil, nil
				}
				return repos, err
			})
		} else {
			slog.Debug("integration not enabled", "integration", i.GetID())
		}
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing repositories", "err", err)
	}

	return utils.Flat(results), nil
}

func (t *thirdPartyIntegrations) WantsToHandleWebhook(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.WantsToHandleWebhook(ctx)
	})
}

func (t *thirdPartyIntegrations) HandleWebhook(ctx core.Context) error {
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return err
	}

	// Close the original body
	defer ctx.Request().Body.Close()

	for _, i := range t.integrations {
		// Create a new ReadCloser for the body
		// otherwise we would reread the body - which is not possible
		ctx.Request().Body = io.NopCloser(bytes.NewBuffer(body))
		if i.WantsToHandleWebhook(ctx) {
			if err := i.HandleWebhook(ctx); err != nil {
				slog.Error("error while handling webhook", "err", err)
				return err
			}
		}
	}

	return nil
}

func (t *thirdPartyIntegrations) GetUsers(org models.Org) []core.User {
	users := []core.User{}
	for _, i := range t.integrations {
		users = append(users, i.GetUsers(org)...)
	}

	return users
}

func (t *thirdPartyIntegrations) HandleEvent(event any) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.HandleEvent(event)
		})
	}

	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) ReopenIssue(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.ReopenIssue(ctx, repoId, dependencyVuln)
		})
	}
	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.CreateIssue(ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug)
		})
	}

	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) CloseIssue(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.CloseIssue(ctx, state, repoId, dependencyVuln)
		})
	}

	_, err := wg.WaitAndCollect()
	return err
}

func NewThirdPartyIntegrations(integrations ...core.ThirdPartyIntegration) *thirdPartyIntegrations {
	return &thirdPartyIntegrations{
		integrations: integrations,
	}
}

// this function returns a string containing a mermaids js flow chart to the given pURL
func renderPathToComponent(componentRepository core.ComponentRepository, assetID uuid.UUID, assetVersionName string, scannerID string, pURL string) (string, error) {

	//basic string to tell markdown that we have a mermaid flow chart with given parameters
	mermaidFlowChart := "mermaid \n %%{init: { 'theme':'dark' } }%%\n flowchart TD\n"

	components, err := componentRepository.LoadPathToComponent(nil, assetVersionName, assetID, pURL, scannerID)
	if err != nil {
		return mermaidFlowChart, err
	}

	tree := assetversion.BuildDependencyTree(components)

	//we get the path to the component as an array of package names
	componentList := []string{}
	current := tree.Root
	for current != nil {
		componentList = append(componentList, current.Name)
		if len(current.Children) > 0 {
			current = current.Children[0]
		} else {
			break
		}
	}

	//now we build the string using this list, every new node need prefix and suffix to work with mermaid. [] are used to prohibit mermaid from interpreting some symbols from the package names as mermaid syntax
	mermaidFlowChart += componentList[0]
	var nodeContent string

	for i, componentName := range componentList[1:] {

		nodeContent, err = beautifyPURL(componentName)
		if err != nil {
			nodeContent = componentName
		}
		mermaidFlowChart = mermaidFlowChart + " --> \n" + "node" + strconv.Itoa(i) + "[" + nodeContent + "]"
	}

	mermaidFlowChart = "```" + mermaidFlowChart + "\n```\n"

	return mermaidFlowChart, nil
}

// function to make purl look more visually appealing
func beautifyPURL(pURL string) (string, error) {
	p, err := packageurl.FromString(pURL)
	if err != nil {
		slog.Error("cannot convert to purl struct")
		return pURL, err
	}
	//if the namespace is empty we don't want any leading slashes
	if p.Namespace == "" {
		return p.Name, nil
	} else {
		return p.Namespace + "/" + p.Name, nil
	}
}
