package auth

import (
	"context"
	"errors"
	ssoauthv1 "github.com/dune6/contracts-sso-service/gen/go/sso"
	"github.com/dune6/sso-auth/internal/services/auth"
	"github.com/dune6/sso-auth/internal/services/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyIdValue = 0

type Auth interface {
	Login(context context.Context,
		email string,
		password string,
		appId int64) (token string, err error)

	RegisterNewUser(context context.Context,
		email string,
		password string,
	) (userId int64, err error)

	IsAdmin(context context.Context, userId int64) (isAdmin bool, err error)
}

type serverAPI struct {
	ssoauthv1.UnimplementedAuthServer
	auth Auth
}

func Register(grpcServer *grpc.Server, auth Auth) {
	ssoauthv1.RegisterAuthServer(grpcServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssoauthv1.LoginRequest,
) (*ssoauthv1.LoginResponse, error) {

	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int64(req.GetAppId()))
	if err == nil {
		if errors.Is(err, auth.ErrorInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssoauthv1.LoginResponse{
		Token: token,
	}, nil
}

func validateLogin(req *ssoauthv1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	if req.GetAppId() == emptyIdValue {
		return status.Error(codes.InvalidArgument, "incorrect app id")
	}
	return nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssoauthv1.RegisterRequest,
) (*ssoauthv1.RegisterResponse, error) {

	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssoauthv1.RegisterResponse{UserId: userId}, nil
}

func validateRegister(req *ssoauthv1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	return nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssoauthv1.IsAdminRequest,
) (*ssoauthv1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return nil, status.Error(codes.NotFound, "app not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssoauthv1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func validateIsAdmin(req *ssoauthv1.IsAdminRequest) error {
	if req.GetUserId() == emptyIdValue {
		return status.Error(codes.InvalidArgument, "userId required")
	}

	return nil
}
