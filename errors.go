package auth

import (
	"errors"
)

var (
	ErrEmailAlreadyUsed error = errors.New("auth: the email is already being used")
)
