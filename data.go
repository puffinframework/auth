package auth

import (
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
	Load()
	Save()
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

func NewSnapshotData(store *snapshot.Store) *SnapshotData {
	return &impl{
		store: store,
		data: *data{
			LastEventDt: 0,
			UserById: make(map[string]User),
			UserIdByEmail: make(map[string]string),
			VerificationByUserId: make(map[string]Verification),
		},
	}
}

func (self *impl) Load() {
}

func (self *impl) Save() {
}
