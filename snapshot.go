package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotStore interface {
	Load()
	Save()
	GetLastEventDt() time.Time
	SetLastEventDt(lastEventDt time.Time)
	CreateUser(user User)
	GetUserId(appId, email string) string
	GetHashedPassword(userId string) []byte
	SetVerification(verification Verification)
	GetVerification(userId string) Verification
}

type implSnapshotStore struct {
	store snapshot.Store
	data  *dataSnapshotStore
}

type dataSnapshotStore struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByAppIdEmail   map[string]string
	VerificationByUserId map[string]Verification
}

func NewSnapshotStore(store snapshot.Store) SnapshotStore {
	return &implSnapshotStore{
		store: store,
		data: &dataSnapshotStore{
			LastEventDt:          time.Unix(0, 0),
			UserById:             make(map[string]User),
			UserIdByAppIdEmail:   make(map[string]string),
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

func (self *implSnapshotStore) CreateUser(user User) {
	key := joinAppIdEmail(user.AppId, user.Email)
	self.data.UserIdByAppIdEmail[key] = user.Id
	self.data.UserById[user.Id] = user
}

func (self *implSnapshotStore) GetUserId(appId, email string) string {
	key := joinAppIdEmail(appId, email)
	return self.data.UserIdByAppIdEmail[key]
}

func (self *implSnapshotStore) GetHashedPassword(userId string) []byte {
	user := self.data.UserById[userId]
	return user.HashedPassword
}

func (self *implSnapshotStore) SetVerification(verification Verification) {
	self.data.VerificationByUserId[verification.UserId] = verification
}

func (self *implSnapshotStore) GetVerification(userId string) Verification {
	return self.data.VerificationByUserId[userId]
}

func joinAppIdEmail(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}
