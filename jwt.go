package auth

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	jwtkey string = "developers Developers DEVELOPERS"
)

func EncodeSession(session Session) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["userId"] = session.UserId
	token.Claims["createdAt"] = session.CreatedAt.Unix()
	sessionToken, err := token.SignedString([]byte(jwtkey))
	if err != nil {
		log.Fatalln("[SignIn] couldn't create jwt", err)
	}
	return sessionToken
}

func DecodeSession(sessionToken string) (Session, error) {
	token, err := jwt.Parse(sessionToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtkey), nil
	})
	if err != nil {
		return Session{}, err
	}
	if !token.Valid {
		return Session{}, ErrJwtNotValid
	}

	userId := token.Claims["userId"].(string)
	createdAt := time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return Session{UserId: userId, CreatedAt: createdAt}, nil
}

func EncodeVerification(verification Verification) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["appId"] = verification.AppId
	token.Claims["email"] = verification.Email
	token.Claims["userId"] = verification.UserId
	verificationToken, err := token.SignedString([]byte(jwtkey))
	if err != nil {
		log.Fatalln("[SignIn] couldn't create jwt", err)
	}
	return verificationToken
}

func DecodeVerification(verificationToken string) (Verification, error) {
	token, err := jwt.Parse(verificationToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtkey), nil
	})
	if err != nil {
		return Verification{}, err
	}
	if !token.Valid {
		return Verification{}, ErrJwtNotValid
	}

	verification := Verification{
		AppId: token.Claims["appId"].(string),
		Email: token.Claims["email"].(string),
		UserId: token.Claims["userId"].(string),
	}
	return verification, nil
}
