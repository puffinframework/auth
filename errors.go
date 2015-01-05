package auth

import (
	"errors"
)

var (
	ErrEmailAlreadyUsed error = errors.New("auth: the email is already being used")
	ErrEmailNotVerified error = errors.New("auth: the email is not verified")
	ErrSignInDenied     error = errors.New("auth: sign in denied")
	ErrJwtNotValid  error = errors.New("auth: JWT is not valid")
)
