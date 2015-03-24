package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
	CreateUser(user User)
	GetUserId(appId, email string) string
	GetHashedPassword(userId string) []byte
	SetHashedPassword(userId string, hashedPassword []byte)
	SetVerification(verification Verification)
	GetVerification(userId string) Verification
	SetReset(reset Reset)
	GetReset(userId string) Reset
	DelReset(userId string)
	IsSuperUser(userId string) bool
	IsAuthorized(userId, authorizationId string) bool
}

type snapshotDataImpl struct {
	LastEventDt          time.Time
	SuperUserById        map[string]SuperUser
	UserById             map[string]User
	UserIdByAppIdEmail   map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
	IsAuthorizedByKey    map[string]bool
}

func NewSnapshotData() SnapshotData {
	return &snapshotDataImpl{
		LastEventDt:          time.Unix(0, 0),
		UserById:             make(map[string]User),
		UserIdByAppIdEmail:   make(map[string]string),
		VerificationByUserId: make(map[string]Verification),
	}
}

func (self *snapshotDataImpl) LoadFrom(ss snapshot.Store) error {
	ss.MustLoadSnapshot("AuthSnapshot", self)
	return nil
}

func (self *snapshotDataImpl) SaveTo(ss snapshot.Store) error {
	ss.MustSaveSnapshot("AuthSnapshot", self)
	return nil
}

func (self *snapshotDataImpl) GetLastEventDt() (time.Time, error) {
	return self.LastEventDt, nil
}

func (self *snapshotDataImpl) SetLastEventDt(lastEventDt time.Time) error {
	self.LastEventDt = lastEventDt
	return nil
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

func (self *snapshotDataImpl) IsSuperUser(userId string) bool {
	superUser := self.SuperUserById[userId]
	return superUser.Id != ""
}

func (self *snapshotDataImpl) IsAuthorized(userId, authorizationId string) bool {
	key := getAuthorizationKey(userId, authorizationId)
	return self.IsAuthorizedByKey[key]
}

func getAuthorizationKey(userId, authorizationId string) string {
	return strings.Join([]string{userId, authorizationId}, "__")
}
