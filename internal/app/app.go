package app

import (
	grpcapp "github.com/dune6/sso-auth/internal/app/grpc"
	authgrpc "github.com/dune6/sso-auth/internal/grpc/auth"
	"log/slog"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	// todo инициализировать хранилище

	// todo init auth service (auth)

	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
