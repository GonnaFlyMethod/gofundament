package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"

	"github.com/GonnaFlyMethod/gofundament/app/api"
	"github.com/GonnaFlyMethod/gofundament/app/common/config"
	"github.com/GonnaFlyMethod/gofundament/app/common/integration"
	"github.com/GonnaFlyMethod/gofundament/app/depcontainer"
)

func main() {
	ctx := context.Background()

	logger := log.
		Output(zerolog.ConsoleWriter{
			Out: os.Stderr,
		}).
		With().Caller().
		Logger()

	if err := config.CheckEnvironmentVars(); err != nil {
		logger.Fatal().Err(err).Msg("can't get environment variables")
	}

	globalConfig := config.BuildFromEnv()

	mongoClient, err := integration.NewMongoConnection(ctx, globalConfig.Database)
	if err != nil {
		logger.Fatal().Err(err).Send()
	}

	// TODO: put the funcs that close connections into graceful shutdown phase
	defer func() {
		if err := mongoClient.Disconnect(ctx); err != nil {
			logger.Error().Err(err).Msg("error occurred while disconnecting from MongoDB server")
		}
	}()

	redisClient, err := integration.NewRedisConnection(ctx, globalConfig.InMemoryStorage)
	if err != nil {
		logger.Fatal().Err(err).Send()
	}

	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Fatal().Err(err).Send()
		}
	}()

	containerWithDependencies := depcontainer.NewDependenciesContainer(
		globalConfig, mongoClient, redisClient)

	handler := api.NewHandler(
		containerWithDependencies.AccountService,
	)

	router := chi.NewRouter()
	router.Use(
		hlog.NewHandler(logger),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			logger.Info().
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Send()
		}),
		hlog.RequestIDHandler("request", "Request-Id"),
	)
	handler.SetUpRoutesAndAccessPolicy(router)

	server := http.Server{
		Addr:              ":8090",
		Handler:           router,
		ReadHeaderTimeout: 3 * time.Second, //nolint:gomnd
	}

	logger.Info().Msg("server is running...")

	if err := server.ListenAndServe(); err != nil {
		logger.Error().Err(err).Msg("error while starting server for listening")
	}
}
