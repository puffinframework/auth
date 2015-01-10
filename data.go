package auth

import (
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
}

type impl struct {
	store *snapshot.Store
	data  *data
}

type data struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByEmail        map[string]string
	VerificationByUserId map[string]Verification
}

func NewSnapshotData(store snapshot.Store) SnapshotData {
	return nil
}

func Load() {
}

func Save() {
}
