package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/dune6/sso-auth/internal/domain/models"
	"github.com/dune6/sso-auth/internal/lib/jwt"
	"github.com/dune6/sso-auth/internal/services/storage"
	"golang.org/x/crypto/bcrypt"
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

var (
	ErrorInvalidCredentials = errors.New("invalid credentials")
	ErrorInvalidAppId       = errors.New("invalid app id")
	ErrorUserExists         = errors.New("user already exists")
)

func (a *Auth) Login(ctx context.Context, email, password string, appId int64) (string, error) {
	const op = "auth.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
		slog.String("appId", fmt.Sprintf("%v", appId)))

	log.Info("attempting to login")
	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, ErrorInvalidCredentials)
		}

		a.log.Info("failed to get user", err.Error())
		return "", fmt.Errorf("%s: %w", op, err)

	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("invalid credentials")
		return "", fmt.Errorf("%s: %w", op, ErrorInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, int(appId))
	if err != nil {
		return "", fmt.Errorf("%s: %s", op, err.Error())
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("user logged in successfully")

	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, password string) (int64, error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate hash password", err.Error())

		return 0, fmt.Errorf("%s: %w", op, ErrorUserExists)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			log.Warn("user already exists")
			return 0, fmt.Errorf("%s: %w", op, ErrorInvalidAppId)
		}
		log.Error("failed to save user", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("User has been registered successfully")

	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	const op = "auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.String("userId", fmt.Sprintf("%v", userId)))

	log.Info("attempting to check if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", err.Error())
			return false, fmt.Errorf("%s: %w", op, ErrorInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("after checking if user is admin:", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
