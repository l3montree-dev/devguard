package middlewares

import (
	"log/slog"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// ExternalEntityProviderOrgSyncMiddleware returns a middleware that triggers a background org sync
// for external entity providers. It rate-limits per user so the sync runs at most once every 15 minutes.
func ExternalEntityProviderOrgSyncMiddleware(externalEntityProviderService shared.ExternalEntityProviderService) shared.MiddlewareFunc {
	limiter := &sync.Map{}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			key := shared.GetSession(ctx).GetUserID()
			now := time.Now()

			if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
				slog.Info("syncing external entity provider orgs", "userID", key)
				limiter.Store(key, now.Add(15*time.Minute))
				// Create a goroutine-safe context to avoid using the request context
				safeCtx := GoroutineSafeContext(ctx)
				go func() {
					if _, err := externalEntityProviderService.SyncOrgs(safeCtx); err != nil {
						slog.Error("could not sync external entity provider orgs", "err", err, "userID", key)
					}
				}()
			}
			return next(ctx)
		}
	}
}

// ExternalEntityProviderRefreshMiddleware returns a middleware that refreshes external-entity-provider projects
// for orgs that are external entities. It rate-limits per org+user combination to once every 15 minutes.
func ExternalEntityProviderRefreshMiddleware(externalEntityProviderService shared.ExternalEntityProviderService) shared.MiddlewareFunc {
	limiter := &sync.Map{}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			org := shared.GetOrg(ctx)

			if org.IsExternalEntity() {
				key := org.GetID().String() + "/" + shared.GetSession(ctx).GetUserID()
				now := time.Now()

				if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
					limiter.Store(key, now.Add(15*time.Minute))

					// Create a goroutine-safe context and capture the values we need
					safeCtx := GoroutineSafeContext(ctx)
					userID := shared.GetSession(ctx).GetUserID()
					orgID := org.GetID()

					go func() {
						err := externalEntityProviderService.RefreshExternalEntityProviderProjects(safeCtx, org, userID)
						if err != nil {
							slog.Error("could not refresh external entity provider projects", "err", err, "orgID", orgID, "userID", userID)
						} else {
							slog.Info("refreshed external entity provider projects", "orgID", orgID, "userID", userID)
						}
					}()
				}
			}

			return next(ctx)
		}
	}
}
