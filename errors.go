package auth

import (
	"errors"
)

var (
	ErrJwtNotValid          error = errors.New("AUTH-00")
	ErrSessionExpired       error = errors.New("AUTH-01")
	ErrEmailAlreadyUsed     error = errors.New("AUTH-02")
	ErrEmailNotVerified     error = errors.New("AUTH-03")
	ErrVerificationDenied   error = errors.New("AUTH-04")
	ErrVerificationExpired  error = errors.New("AUTH-05")
	ErrSignInDenied         error = errors.New("AUTH-06")
	ErrChangePasswordDenied error = errors.New("AUTH-07")
	ErrResetPasswordDenied  error = errors.New("AUTH-08")
	ErrResetPasswordExpired error = errors.New("AUTH-09")
	ErrNotAuthorized        error = errors.New("AUTH-10")
)
