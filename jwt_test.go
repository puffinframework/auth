package auth_test

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/puffinframework/auth"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["data"] = "a b c"
	tokenStr, err := token.SignedString([]byte("right key"))
	assert.Nil(t, err)

	token1, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte("right key"), nil
	})
	assert.Nil(t, err)
	assert.True(t, token1.Valid)
	assert.Equal(t, "a b c", token1.Claims["data"])

	token2, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte("wrong key"), nil
	})
	assert.NotNil(t, err)
	assert.False(t, token2.Valid)
	assert.Equal(t, "a b c", token2.Claims["data"])
}

func TestSessionEncoding(t *testing.T) {
	userId := "user-1"
	createdAt := time.Unix(123, 0)

	sessionToken := auth.EncodeSession(auth.Session{UserId: userId, CreatedAt: createdAt})

	session, err := auth.DecodeSession(sessionToken)
	assert.Nil(t, err)
	assert.Equal(t, userId, session.UserId)
	assert.Equal(t, createdAt, session.CreatedAt)
}
