package middlewares

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
)

// ProviderIDMiddleware extracts the :providerID URL param, normalizes it, stores it in the context,
// and rejects IDs that collide with a configured GitLab integration.
func ProviderIDMiddleware(gitlabIntegrations map[string]*gitlabint.GitlabOauth2Config) shared.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			providerID := ctx.Param("providerID")
			providerID = strings.TrimSuffix(providerID, "/")
			providerID = "ext:" + providerID // prefix to avoid collisions with other provider IDs in the future
			if providerID == "" {
				return echo.NewHTTPError(400, "providerID is required")
			}
			if _, isGitLab := gitlabIntegrations[providerID]; isGitLab {
				return echo.NewHTTPError(400, "providerID is reserved")
			}
			shared.SetProviderID(ctx, providerID)
			return next(ctx)
		}
	}
}

// ExternalEntityProviderOrgSyncMiddleware returns a middleware that triggers a background org sync
// for external entity providers. It rate-limits per session owner so the sync runs at most once every 15 minutes.
func ExternalEntityProviderOrgSyncMiddleware(externalEntityProviderService shared.ExternalEntityProviderService) shared.MiddlewareFunc {
	limiter := &sync.Map{}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			session := shared.GetSession(ctx)
			key := session.GetActorID()
			ownerType := session.GetSessionActorType()

			if ownerType != shared.SessionActorUser {
				return next(ctx)
			}

			now := time.Now()

			if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
				slog.Info("syncing external entity provider orgs", "actorID", key, "actorType", string(ownerType))
				limiter.Store(key, now.Add(15*time.Minute))
				safeCtx := GoroutineSafeContext(ctx)
				go func() {
					tracedCtx, span := otel.Tracer("devguard").Start(context.Background(), "sync-orgs")
					defer span.End()
					safeCtx.SetRequest(safeCtx.Request().WithContext(tracedCtx))
					if _, err := externalEntityProviderService.SyncOrgs(safeCtx); err != nil {
						span.RecordError(err)
						slog.Error("could not sync external entity provider orgs", "err", err, "actorID", key, "actorType", string(ownerType))
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
			session := shared.GetSession(ctx)
			// check if user session
			if session.GetSessionActorType() != shared.SessionActorUser {
				return next(ctx)
			}

			if org.IsExternalEntity() {
				key := org.GetID().String() + "/" + session.GetActorID()
				now := time.Now()

				if value, ok := limiter.Load(key); !ok || now.After(value.(time.Time)) {
					limiter.Store(key, now.Add(15*time.Minute))

					safeCtx := GoroutineSafeContext(ctx)
					orgID := org.GetID()

					go func() {
						tracedCtx, span := otel.Tracer("devguard").Start(context.Background(), "refresh-external-entity-provider")
						defer span.End()
						safeCtx.SetRequest(safeCtx.Request().WithContext(tracedCtx))
						err := externalEntityProviderService.RefreshExternalEntityProviderProjects(safeCtx, org, session)
						if err != nil {
							span.RecordError(err)
							slog.Error("could not refresh external entity provider projects", "err", err, "orgID", orgID, "actorID", session.GetActorID(), "traceID", span.SpanContext().TraceID())
						} else {
							slog.Info("refreshed external entity provider projects", "orgID", orgID, "actorID", session.GetActorID(), "traceID", span.SpanContext().TraceID())
						}
					}()
				}
			}

			return next(ctx)
		}
	}
}
