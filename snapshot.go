package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
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

type snapshotDataImpl struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByAppIdEmail   map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
}

func NewSnapshotData() SnapshotData {
	return &snapshotDataImpl{
		LastEventDt:          time.Unix(0, 0),
		UserById:             make(map[string]User),
		UserIdByAppIdEmail:   make(map[string]string),
		VerificationByUserId: make(map[string]Verification),
	}
}

func (self *snapshotDataImpl) LoadFrom(ss snapshot.Store) {
	ss.MustLoadSnapshot("AuthSnapshot", self)
}

func (self *snapshotDataImpl) SaveTo(ss snapshot.Store) {
	ss.MustSaveSnapshot("AuthSnapshot", self)
}

func (self *snapshotDataImpl) GetLastEventDt() time.Time {
	return self.LastEventDt
}

func (self *snapshotDataImpl) SetLastEventDt(lastEventDt time.Time) {
	self.LastEventDt = lastEventDt
}

func (self *snapshotDataImpl) CreateUser(user User) {
	key := joinAppIdEmail(user.AppId, user.Email)
	self.UserIdByAppIdEmail[key] = user.Id
	self.UserById[user.Id] = user
}

func (self *snapshotDataImpl) GetUserId(appId, email string) string {
	key := joinAppIdEmail(appId, email)
	return self.UserIdByAppIdEmail[key]
}

func (self *snapshotDataImpl) GetHashedPassword(userId string) []byte {
	user := self.UserById[userId]
	return user.HashedPassword
}

func (self *snapshotDataImpl) SetHashedPassword(userId string, hashedPassword []byte) {
	user := self.UserById[userId]
	user.HashedPassword = hashedPassword
	self.UserById[userId] = user
}

func (self *snapshotDataImpl) SetVerification(verification Verification) {
	self.VerificationByUserId[verification.UserId] = verification
}

func (self *snapshotDataImpl) GetVerification(userId string) Verification {
	return self.VerificationByUserId[userId]
}

func joinAppIdEmail(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}

func (self *snapshotDataImpl) SetReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
}

func (self *snapshotDataImpl) GetReset(userId string) Reset {
	return self.ResetByUserId[userId]
}

func (self *snapshotDataImpl) DelReset(userId string) {
	delete(self.ResetByUserId, userId)
}
