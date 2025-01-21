package storage

import "errors"

var (
	ErrUserExist    = errors.New("user exist")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app not found")
)
