package serverhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/scotthaleen/go-app"
	"github.com/scotthaleen/go-toolbelt/httpserver"
	"github.com/scotthaleen/go-toolbelt/localgateway"
	"github.com/scotthaleen/go-toolbelt/processlock"
	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/adapterapi"
	"github.com/scotthaleen/px/internal/apphome"
	"github.com/scotthaleen/px/internal/database"
	"github.com/scotthaleen/px/internal/localipc"
	"github.com/scotthaleen/px/internal/membership"
	"github.com/scotthaleen/px/internal/rendezvous"
	"github.com/scotthaleen/px/internal/rendezvousapi"
	"github.com/scotthaleen/px/internal/serveradmin"
	"github.com/scotthaleen/px/internal/stunserver"
)

func RunServer(ctx context.Context, paths apphome.Paths, listenAddress, stunAddress string, trustedProxyCIDRs []string, logger *slog.Logger) error {
	trustedProxies, err := rendezvousapi.ParseTrustedProxyCIDRs(trustedProxyCIDRs)
	if err != nil {
		return err
	}
	if err := paths.EnsureServer(); err != nil {
		return err
	}
	authority, err := membership.Load(paths.ServerAuthorityKey, paths.ServerIdentity)
	if err != nil {
		return err
	}
	cfg, err := database.Config(database.KindServer, paths.ServerDatabase)
	if err != nil {
		return err
	}
	databaseStore := sqlite.New(cfg)
	factNotifications := make(chan struct{}, adapterapi.MaxDoorbellSubscribers)
	members := membership.NewStoreProvider(databaseStore.DB, authority, membership.DefaultMaxPending, membership.WithFactNotifications(factNotifications))
	doorbells := adapterapi.NewBroker(factNotifications)
	hub := rendezvousapi.NewHub()
	operational := rendezvousapi.NewOperationalState()
	publicHandler := rendezvousapi.New(members, authority, hub, logger, rendezvousapi.WithTrustedProxies(trustedProxies), rendezvousapi.WithOperationalState(operational))
	publicServer := httpserver.New(
		httpserver.Config{
			Addr:              listenAddress,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       time.Minute,
		},
		publicHandler.Handler(),
		httpserver.WithLogger(logger),
	)
	serverContext, requestShutdown := context.WithCancel(ctx)
	defer requestShutdown()
	lock := processlock.New(processlock.Config{Path: paths.ServerLock, Name: "server process lock"})
	adapterGatewayConfig := localgateway.DefaultConfig(paths.ServerAdapterEndpoint)
	adapterGatewayConfig.Name = "enrollment adapter IPC server"
	adapterGatewayConfig.PipeInputBufferBytes = localipc.MaxRequestBytes
	adapterGatewayConfig.PipeOutputBufferBytes = 4 << 10
	adapterServer := localgateway.New(adapterGatewayConfig, adapterapi.New(members, doorbells), localgateway.WithLogger(logger))
	adminGatewayConfig := localgateway.DefaultConfig(paths.ServerAdminEndpoint)
	adminGatewayConfig.Name = "server administration IPC server"
	adminServer := localgateway.New(adminGatewayConfig, serveradmin.New(members, hub, requestShutdown, serveradmin.WithOperationalState(operational), serveradmin.WithLogger(logger)), localgateway.WithLogger(logger))
	httpReadiness := app.NewComponent(
		app.WithName("rendezvous HTTP readiness"),
		app.WithOnStart(func(context.Context) error {
			operational.SetHTTPReady(true)
			return nil
		}),
		app.WithOnStop(func(context.Context) error {
			operational.SetHTTPReady(false)
			return nil
		}),
	)
	components := []app.StartupItem{app.Managed(lock), app.Registered(databaseStore), app.Managed(doorbells), app.Managed(adapterServer), app.Managed(publicServer), app.Managed(httpReadiness), app.Managed(hub), app.Managed(adminServer)}
	if stunAddress != "" {
		components = append(components, app.Managed(stunserver.New(stunAddress, logger)))
	}
	readiness := app.NewComponent(
		app.WithName("rendezvous lifecycle readiness"),
		app.WithOnStart(func(context.Context) error {
			operational.SetLifecycleReady(true)
			return nil
		}),
		app.WithOnStop(func(context.Context) error {
			operational.SetLifecycleReady(false)
			return nil
		}),
	)
	components = append(components, app.Managed(readiness))
	a := app.New(
		serverContext,
		app.WithLogger(logger),
		app.WithDependency(paths),
		app.WithSequentialStartup(components...),
	)
	logger.Info("starting PX rendezvous server", "home", paths.Root, "server_id", authority.ServerID())
	if err := a.Run(); err != nil {
		if errors.Is(err, processlock.ErrLocked) {
			return errors.New("PX server is already running")
		}
		return fmt.Errorf("run server: %w", err)
	}
	return nil
}

func RunSignalServer(ctx context.Context, listenAddress string, logger *slog.Logger) error {
	hub := rendezvous.New(rendezvous.Config{})
	server := httpserver.New(
		httpserver.Config{
			Addr:              listenAddress,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		},
		hub.Handler(),
		httpserver.WithLogger(logger),
	)
	a := app.New(
		ctx,
		app.WithLogger(logger),
		app.WithSequentialStartup(app.Managed(server)),
	)
	if err := a.Run(); err != nil {
		return fmt.Errorf("run probe signaling server: %w", err)
	}
	return nil
}
