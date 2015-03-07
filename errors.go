package auth

import (
	"errors"
)

var (
	ErrEmailAlreadyUsed     error = errors.New("auth: the email is already being used")
	ErrEmailNotVerified     error = errors.New("auth: the email is not verified")
	ErrVerificationDenied   error = errors.New("auth: verification denied")
	ErrSignInDenied         error = errors.New("auth: sign in denied")
	ErrChangePasswordDenied error = errors.New("auth: change password denied")
	ErrResetPasswordDenied  error = errors.New("auth: reset password denied")
	ErrJwtNotValid          error = errors.New("auth: JWT is not valid")
)
