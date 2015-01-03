package auth_test

import (
	"testing"
	"time"

	"github.com/puffinframework/auth"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	userId := "user-1"
	createdAt := time.Unix(123, 0)

	tokenStr := auth.EncodeSession(auth.Session{UserId: userId, CreatedAt: createdAt})

	session, err := auth.DecodeSession(tokenStr)
	assert.Nil(t, err)
	assert.Equal(t, userId, session.UserId)
	assert.Equal(t, createdAt, session.CreatedAt)
}
