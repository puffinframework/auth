package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type Snapshot interface {
	LoadFrom(ss snapshot.Store)
	SaveTo(ss snapshot.Store)
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
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByAppIdEmail   map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
}

func NewSnapshot() Snapshot {
	return &snapshotImpl{
		LastEventDt: time.Unix(0, 0),
		UserById: make(map[string]User),
		UserIdByAppIdEmail: make(map[string]string),
		VerificationByUserId: make(map[string]Verification),
	}
}

func (self *snapshotImpl) LoadFrom(ss snapshot.Store) {
	ss.MustLoadSnapshot("AuthSnapshot", self)
}

func (self *snapshotImpl) SaveTo(ss snapshot.Store) {
	ss.MustSaveSnapshot("AuthSnapshot", self)
}

func (self *snapshotImpl) GetLastEventDt() time.Time {
	return self.LastEventDt
}

func (self *snapshotImpl) SetLastEventDt(lastEventDt time.Time) {
	self.LastEventDt = lastEventDt
}

func (self *snapshotImpl) CreateUser(user User) {
	key := joinAppIdEmail(user.AppId, user.Email)
	self.UserIdByAppIdEmail[key] = user.Id
	self.UserById[user.Id] = user
}

func (self *snapshotImpl) GetUserId(appId, email string) string {
	key := joinAppIdEmail(appId, email)
	return self.UserIdByAppIdEmail[key]
}

func (self *snapshotImpl) GetHashedPassword(userId string) []byte {
	user := self.UserById[userId]
	return user.HashedPassword
}

func (self *snapshotImpl) SetHashedPassword(userId string, hashedPassword []byte) {
	user := self.UserById[userId]
	user.HashedPassword = hashedPassword
	self.UserById[userId] = user
}

func (self *snapshotImpl) SetVerification(verification Verification) {
	self.VerificationByUserId[verification.UserId] = verification
}

func (self *snapshotImpl) GetVerification(userId string) Verification {
	return self.VerificationByUserId[userId]
}

func joinAppIdEmail(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}

func (self *snapshotImpl) SetReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
}

func (self *snapshotImpl) GetReset(userId string) Reset {
	return self.ResetByUserId[userId]
}

func (self *snapshotImpl) DelReset(userId string) {
	delete(self.ResetByUserId, userId)
}
