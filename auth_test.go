package auth_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type authConfig struct {
	EventStore struct {
		LeveldbDir string
	}
	SnapshotStore struct {
		LeveldbDir string
	}
}

func Test(t *testing.T) {
	assert.Nil(t, nil)
}
