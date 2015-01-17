package auth

import (
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotStore interface {
	Load()
	Save()
	GetLastEventDt() time.Time
	SetLastEventDt(lastEventDt time.Time)
	GetUserId(appId, email string) string
	CreateUser(user User)
	SetVerification(verification Verification)
	GetHashedPassword(userId string) []byte
	GetVerification(userId string) Verification
}

type implSnapshotStore struct {
	store snapshot.Store
	data  *dataSnapshotStore
}

type dataSnapshotStore struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByEmail        map[string]string
	VerificationByUserId map[string]Verification
}

func NewSnapshotStore(store snapshot.Store) SnapshotStore {
	return &implSnapshotStore{
		store: store,
		data: &dataSnapshotStore{
			LastEventDt:          time.Unix(0, 0),
			UserById:             make(map[string]User),
			UserIdByEmail:        make(map[string]string),
			VerificationByUserId: make(map[string]Verification),
		},
	}
}

func (self *implSnapshotStore) Load() {
	self.store.MustLoadSnapshot("AuthSnapshot", self.data)
}

func (self *implSnapshotStore) Save() {
	self.store.MustSaveSnapshot("AuthSnapshot", self.data)
}

func (self *implSnapshotStore) GetLastEventDt() time.Time {
	return self.data.LastEventDt
}

func (self *implSnapshotStore) SetLastEventDt(lastEventDt time.Time) {
	self.data.LastEventDt = lastEventDt
}

func (self *implSnapshotStore) GetUserId(appId, email string) string {
	// TODO should also consider appIdd
	return self.data.UserIdByEmail[email]
}

func (self *implSnapshotStore) CreateUser(user User) {
	self.data.UserById[user.Id] = user
	self.data.UserIdByEmail[user.Email] = user.Id
}

func (self *implSnapshotStore) SetVerification(verification Verification) {
	self.data.VerificationByUserId[verification.UserId] = verification
}

func (self *implSnapshotStore) GetHashedPassword(userId string) []byte {
	user := self.data.UserById[userId]
	return user.HashedPassword
}

func (self *implSnapshotStore) GetVerification(userId string) Verification {
	return self.data.VerificationByUserId[userId]
}
