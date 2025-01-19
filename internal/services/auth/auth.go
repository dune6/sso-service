package auth

import (
	"context"
	"github.com/dune6/sso-auth/internal/domain/models"
	"log/slog"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userProvider UserProvider
	appProvider  AppProvider
	userSaver    UserSaver
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context,
		email string,
		passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int) (models.App, error)
}

// New returns a new instance of Auth service
func New(
	log *slog.Logger,
	userProvider UserProvider,
	appProvider AppProvider,
	userSaver UserSaver,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:          log,
		userProvider: userProvider,
		appProvider:  appProvider,
		userSaver:    userSaver,
		tokenTTL:     tokenTTL,
	}
}
