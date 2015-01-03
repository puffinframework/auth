package auth

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	JWT_KEY string = "developers Developers DEVELOPERS"
)

func EncodeSession(session Session) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["userId"] = session.UserId
	token.Claims["createdAt"] = session.CreatedAt.Unix()
	tokenStr, err := token.SignedString([]byte(JWT_KEY))
	if err != nil {
		log.Fatalln("[SignIn] couldn't create jwt", err)
	}
	return tokenStr
}

func DecodeSession(tokenStr string) (Session, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_KEY), nil
	})
	if err != nil {
		return Session{}, err
	}
	if !token.Valid {
		return Session{}, ErrSessionNotValid
	}

	userId := token.Claims["userId"].(string)
	createdAt := time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return Session{UserId: userId, CreatedAt: createdAt}, nil
}
