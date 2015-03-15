package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type Snapshot interface {
	Load()
	Save()
	GetLastEventDt() time.Time
	SetLastEventDt(lastEventDt time.Time)

	CreateUser(user User)
	GetUserId(appId, email string) string
	GetHashedPassword(userId string) []byte
	SetHashedPassword(userId string, hashedPassword []byte)
	SetVerification(verification Verification)
	GetVerification(userId string) Verification
	SetReset(reset Reset)
	GetReset(userId string) Reset
	DelReset(userId string)
}

type snapshotImpl struct {
	store snapshot.Store
	data  *snapshotData
}

type snapshotData struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByAppIdEmail   map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
}

func NewSnapshot(store snapshot.Store) Snapshot {
	return &snapshotImpl{
		store: store,
		data: &snapshotData{
			LastEventDt:          time.Unix(0, 0),
			UserById:             make(map[string]User),
			UserIdByAppIdEmail:   make(map[string]string),
			VerificationByUserId: make(map[string]Verification),
		},
	}
}

func (self *snapshotImpl) Load() {
	self.store.MustLoadSnapshot("AuthSnapshot", self.data)
}

func (self *snapshotImpl) Save() {
	self.store.MustSaveSnapshot("AuthSnapshot", self.data)
}

func (self *snapshotImpl) GetLastEventDt() time.Time {
	return self.data.LastEventDt
}

func (self *snapshotImpl) SetLastEventDt(lastEventDt time.Time) {
	self.data.LastEventDt = lastEventDt
}

func (self *snapshotImpl) CreateUser(user User) {
	key := joinAppIdEmail(user.AppId, user.Email)
	self.data.UserIdByAppIdEmail[key] = user.Id
	self.data.UserById[user.Id] = user
}

func (self *snapshotImpl) GetUserId(appId, email string) string {
	key := joinAppIdEmail(appId, email)
	return self.data.UserIdByAppIdEmail[key]
}

func (self *snapshotImpl) GetHashedPassword(userId string) []byte {
	user := self.data.UserById[userId]
	return user.HashedPassword
}

func (self *snapshotImpl) SetHashedPassword(userId string, hashedPassword []byte) {
	user := self.data.UserById[userId]
	user.HashedPassword = hashedPassword
	self.data.UserById[userId] = user
}

func (self *snapshotImpl) SetVerification(verification Verification) {
	self.data.VerificationByUserId[verification.UserId] = verification
}

func (self *snapshotImpl) GetVerification(userId string) Verification {
	return self.data.VerificationByUserId[userId]
}

func joinAppIdEmail(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}

func (self *snapshotImpl) SetReset(reset Reset) {
	self.data.ResetByUserId[reset.UserId] = reset
}

func (self *snapshotImpl) GetReset(userId string) Reset {
	return self.data.ResetByUserId[userId]
}

func (self *snapshotImpl) DelReset(userId string) {
	delete(self.data.ResetByUserId, userId)
}
