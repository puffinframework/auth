package auth

import (
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
	Load()
	Save()
	GetLastEventDt() time.Time
	SetLastEventDt(lastEventDt time.Time)
	GetUserId(appId, email string) string
}

type impl struct {
	store snapshot.Store
	data  *data
}

type data struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByEmail        map[string]string
	VerificationByUserId map[string]Verification
}

func NewSnapshotData(store snapshot.Store) SnapshotData {
	return &impl{
		store: store,
		data: &data{
			LastEventDt:          time.Unix(0, 0),
			UserById:             make(map[string]User),
			UserIdByEmail:        make(map[string]string),
			VerificationByUserId: make(map[string]Verification),
		},
	}
}

func (self *impl) Load() {
	self.store.MustLoadSnapshot("AuthSnapshot", self.data)
}

func (self *impl) Save() {
	self.store.MustSaveSnapshot("AuthSnapshot", self.data)
}

func (self *impl) GetLastEventDt() time.Time {
	return self.data.LastEventDt
}

func (self *impl) SetLastEventDt(lastEventDt time.Time) {
	self.data.LastEventDt = lastEventDt
}

func (self *impl) GetUserId(appId, email string) string {
	// TODO should also consider appIdd
	return self.data.UserIdByEmail[email]
}
