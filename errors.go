package auth

import (
	"errors"
)

var (
	ErrJwtNotValid          error = errors.New("AUTH-00")
	ErrEmailAlreadyUsed     error = errors.New("AUTH-01")
	ErrEmailNotVerified     error = errors.New("AUTH-02")
	ErrVerificationDenied   error = errors.New("AUTH-03")
	ErrSignInDenied         error = errors.New("AUTH-04")
	ErrChangePasswordDenied error = errors.New("AUTH-05")
	ErrResetPasswordDenied  error = errors.New("AUTH-06")
)
