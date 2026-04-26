// Copyright (C) 2023 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/fixedversion"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/vulndb"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/l3montree-dev/devguard/router"
	"github.com/l3montree-dev/devguard/services"

	"github.com/l3montree-dev/devguard/database"

	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	_ "net/http/pprof"

	_ "github.com/lib/pq"
)

var release string // Will be filled at build time

//	@title			DevGuard API
//	@version		v1
//	@description	DevGuard Backend. Secure your Software Supply Chain. Attestation-based compliance as Code, manage your CVEs seamlessly, Integrate your Vulnerability Scanners, Security Framework Documentation made easy. OWASP Incubating Project

//	@contact.name	Support
//	@contact.url	https://github.com/l3montree-dev/devguard/issues

//	@license.name	AGPL-3
//	@license.url	https://github.com/l3montree-dev/devguard/blob/main/LICENSE.txt

// @servers.url {scheme}://{host}:{port}/api/v1
// @servers.description Development server
// @servers.variables.enum scheme http
// @servers.variables.enum scheme https
// @servers.variables.default scheme http
// @servers.variables.default host localhost
// @servers.variables.default port 8080

// @servers.url https://api.devguard.org/api/v1
// @servers.description Production server

//	@securityDefinitions.apikey	CookieAuth
//	@in							cookie
//	@name						ory_kratos_session
//	@description				Session-based authentication using Ory Kratos

// @securityDefinitions.apikey	PATAuth
// @in							header
// @name						X-Signature
// @description				Personal Access Token authentication using HTTP request signing. Requires X-Signature and X-Fingerprint headers.
func main() {
	//os.Setenv("TZ", "UTC")
	shared.LoadConfig() // nolint: errcheck
	shared.InitLogger()

	if os.Getenv("ERROR_TRACKING_DSN") != "" {
		initSentry()
		if sampleRate := tracesSampleRate(); sampleRate > 0 {
			initTracer(sampleRate)
		}

		// Catch panics
		defer func() {
			if err := recover(); err != nil {
				// This is a catch-all. To see the stack trace in GlitchTip open the Stacktrace below
				sentry.CurrentHub().Recover(err)
				monitoring.RecoverAndAlert("could not recover from panic in main", fmt.Errorf("panic: %v", err))
				sentry.Flush(time.Second * 5)
			}
		}()
	}

	app := fx.New(
		fx.WithLogger(func() fxevent.Logger { return &fxErrorLogger{} }),
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.Provide(api.NewServer),
		database.Module,
		repositories.Module,
		controllers.ControllerModule,
		services.ServiceModule,
		router.RouterModule,
		accesscontrol.AccessControlModule,
		integrations.Module,
		vulndb.Module,
		daemons.Module,
		fixedversion.Module,
		// we need to invoke all routers to register their routes
		fx.Invoke(func(OrgRouter router.OrgRouter) {}),
		fx.Invoke(func(ProjectRouter router.ProjectRouter) {}),
		fx.Invoke(func(SessionRouter router.SessionRouter) {}),
		fx.Invoke(func(ArtifactRouter router.ArtifactRouter) {}),
		fx.Invoke(func(AssetRouter router.AssetRouter) {}),
		fx.Invoke(func(AssetVersionRouter router.AssetVersionRouter) {}),
		fx.Invoke(func(DependencyVulnRouter router.DependencyVulnRouter) {}),
		fx.Invoke(func(FirstPartyVulnRouter router.FirstPartyVulnRouter) {}),
		fx.Invoke(func(LicenseRiskRouter router.LicenseRiskRouter) {}),
		fx.Invoke(func(ShareRouter router.ShareRouter) {}),
		fx.Invoke(func(VulnDBRouter router.VulnDBRouter) {}),
		fx.Invoke(func(dependencyProxyRouter router.DependencyProxyRouter) {}),
		fx.Invoke(func(ociRegistryRouter router.OCIRegistryRouter) {}),
		fx.Invoke(func(FalsePositiveRuleRouter router.VEXRuleRouter) {}),
		fx.Invoke(func(ExternalReferenceRouter router.ExternalReferenceRouter) {}),
		fx.Invoke(func(lc fx.Lifecycle, server api.Server) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					go server.Start() // start in background
					return nil
				},
			})
		}),
		fx.Invoke(func(lc fx.Lifecycle, daemonRunner shared.DaemonRunner) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					go daemonRunner.Start(ctx) // start in background
					return nil
				},
			})
		}),
	)

	app.Run()
}

type fxErrorLogger struct{}

func (l *fxErrorLogger) LogEvent(event fxevent.Event) {
	switch e := event.(type) {
	case *fxevent.OnStartExecuted:
		if e.Err != nil {
			slog.Error("fx: OnStart hook failed", "caller", e.CallerName, "err", e.Err)
		}
	case *fxevent.OnStopExecuted:
		if e.Err != nil {
			slog.Error("fx: OnStop hook failed", "caller", e.CallerName, "err", e.Err)
		}
	case *fxevent.Supplied:
		if e.Err != nil {
			slog.Error("fx: supply failed", "type", e.TypeName, "err", e.Err)
		}
	case *fxevent.Provided:
		if e.Err != nil {
			slog.Error("fx: provide failed", "constructor", e.ConstructorName, "err", e.Err)
		}
	case *fxevent.Decorated:
		if e.Err != nil {
			slog.Error("fx: decorate failed", "decorator", e.DecoratorName, "err", e.Err)
		}
	case *fxevent.Invoked:
		if e.Err != nil {
			slog.Error("fx: invoke failed", "function", e.FunctionName, "err", e.Err)
		}
	case *fxevent.Started:
		if e.Err != nil {
			slog.Error("fx: start failed", "err", e.Err)
		}
	case *fxevent.Stopped:
		if e.Err != nil {
			slog.Error("fx: stop failed", "err", e.Err)
		}
	}
}

func tracesSampleRate() float64 {
	val := os.Getenv("TRACES_SAMPLE_RATE")
	if val == "" {
		return 0
	}
	rate, err := strconv.ParseFloat(val, 64)
	if err != nil {
		slog.Warn("invalid TRACES_SAMPLE_RATE, tracing disabled", "value", val)
		return 0
	}
	return rate
}

func initTracer(sampleRate float64) {
	var processors []sdktrace.SpanProcessor

	// When OTEL_TRACES_EXPORTER=stdout, print spans to stderr for local debugging.
	if os.Getenv("OTEL_TRACES_EXPORTER") == "stdout" {
		exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			slog.Warn("failed to create stdout trace exporter", "err", err)
		} else {
			processors = append(processors, sdktrace.NewSimpleSpanProcessor(exp))
		}
	}

	// OTEL_EXPORTER_OTLP_ENDPOINT selects transport by scheme:
	//   grpc://host:port   → gRPC, no TLS  (e.g. local Jaeger)
	//   grpcs://host:port  → gRPC, TLS
	//   http://host:port   → HTTP, no TLS
	//   https://host:port  → HTTP, TLS
	// Optional: OTEL_EXPORTER_BASIC_AUTH_USERNAME / OTEL_EXPORTER_BASIC_AUTH_PASSWORD
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		var (
			exp     sdktrace.SpanExporter
			err     error
			headers map[string]string
		)

		if user, pass := os.Getenv("OTEL_EXPORTER_BASIC_AUTH_USERNAME"), os.Getenv("OTEL_EXPORTER_BASIC_AUTH_PASSWORD"); user != "" && pass != "" {
			encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			headers = map[string]string{"Authorization": "Basic " + encoded}
		}

		u, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			slog.Warn("failed to parse OTEL_EXPORTER_OTLP_ENDPOINT", "err", parseErr, "endpoint", endpoint)
		} else {
			switch u.Scheme {
			case "grpc":
				exp, err = otlptracegrpc.New(context.Background(),
					otlptracegrpc.WithEndpoint(u.Host),
					otlptracegrpc.WithInsecure(),
					otlptracegrpc.WithHeaders(headers),
				)
			case "https":
				exp, err = otlptracehttp.New(context.Background(),
					otlptracehttp.WithEndpointURL(endpoint),
					otlptracehttp.WithHeaders(headers),
				)
			default: // http
				exp, err = otlptracehttp.New(context.Background(),
					otlptracehttp.WithEndpointURL(endpoint),
					otlptracehttp.WithInsecure(),
					otlptracehttp.WithHeaders(headers),
				)
			}
		}
		if err != nil {
			slog.Warn("failed to create OTLP trace exporter", "err", err, "endpoint", endpoint)
		} else {
			processors = append(processors, sdktrace.NewBatchSpanProcessor(exp))
			slog.Info("OTLP trace exporter enabled", "endpoint", endpoint)
		}
	}

	res, resErr := resource.New(context.Background(),
		resource.WithAttributes(semconv.ServiceNameKey.String("devguard")),
	)
	if resErr != nil {
		slog.Warn("failed to create OTel resource", "err", resErr)
		res = resource.Default()
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
		sdktrace.WithResource(res),
	}
	for _, p := range processors {
		opts = append(opts, sdktrace.WithSpanProcessor(p))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	slog.Info("tracing initialized", "sample_rate", sampleRate)
}

func initSentry() {
	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "dev"
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:         os.Getenv("ERROR_TRACKING_DSN"),
		Environment: environment,
		Release:     release,

		// Configures whether SDK should generate and attach stack traces to pure
		// capture message calls.
		AttachStacktrace: true,

		// If this flag is enabled, certain personally identifiable information (PII) is added by active integrations.
		// By default, no such data is sent.
		SendDefaultPII: false,
	})

	if err != nil {
		slog.Error("Failed to init logger", "err", err)
	}
}

// AllModules combines all FX modules for easy import
var AllModules = fx.Options(
	controllers.ControllerModule,
	services.ServiceModule,
)
