package apphost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/scotthaleen/go-app"
	"github.com/scotthaleen/go-toolbelt/localgateway"
	"github.com/scotthaleen/go-toolbelt/processlock"
	"github.com/scotthaleen/go-toolbelt/sqlite"
	"github.com/scotthaleen/px/internal/agentapi"
	"github.com/scotthaleen/px/internal/apphome"
	contextstate "github.com/scotthaleen/px/internal/contexts"
	"github.com/scotthaleen/px/internal/database"
)

func RunAgent(ctx context.Context, paths apphome.Paths, logger *slog.Logger) error {
	if err := paths.EnsureAgent(); err != nil {
		return err
	}
	cfg, err := database.Config(database.KindAgent, paths.AgentDatabase)
	if err != nil {
		return err
	}
	store := sqlite.New(cfg)
	contextManager := contextstate.NewManager(paths, store.DB, logger)
	agentContext, requestShutdown := context.WithCancel(ctx)
	defer requestShutdown()
	lock := processlock.New(processlock.Config{Path: paths.AgentLock, Name: "agent process lock"})
	gatewayConfig := localgateway.DefaultConfig(paths.AgentEndpoint)
	gatewayConfig.Name = "agent IPC server"
	server := localgateway.New(gatewayConfig, agentapi.New(requestShutdown, logger, contextManager), localgateway.WithLogger(logger))
	readiness := app.NewComponent(
		app.WithName("agent readiness"),
		app.WithOnStart(func(ctx context.Context) error {
			logger.InfoContext(ctx, "PX agent ready", "event", "agent.ready")
			contextManager.Activate()
			return nil
		}),
		app.WithOnStop(func(ctx context.Context) error {
			logger.InfoContext(ctx, "PX agent stopping", "event", "agent.stopping")
			return nil
		}),
	)
	a := app.New(
		agentContext,
		app.WithLogger(logger),
		app.WithDependency(paths),
		app.WithSequentialStartup(app.Managed(lock), app.Registered(store), app.Managed(contextManager), app.Managed(server), app.Managed(readiness)),
	)
	logger.Info("starting PX agent", "event", "agent.starting", "home", paths.Root)
	if err := a.Run(); err != nil {
		if errors.Is(err, processlock.ErrLocked) {
			return errors.New("PX agent is already running")
		}
		return fmt.Errorf("run agent: %w", err)
	}
	return nil
}
