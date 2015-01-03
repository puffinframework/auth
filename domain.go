package auth

import (
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	SIGNED_UP string = "SignedUp"
	SIGNED_IN string = "SignedIn"
	JWT_KEY   string = "developers Developers DEVELOPERS"
)

type User struct {
	Id             string
	AppId          string
	Email          string
	HashedPassword []byte
}

type UserById map[string]User

type UserIdByEmail map[string]string

type AuthToken struct {
	UserId    string
	CreatedAt time.Time
}

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

type SignedInEvent struct {
	Header event.Header
	Data   AuthToken
}

func SignUp(appId, email, password string, userById UserById, userIdByEmail UserIdByEmail) (SignedUpEvent, error) {
	userId := userIdByEmail[email]
	if userById[userId].AppId == appId {
		return SignedUpEvent{}, ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return SignedUpEvent{}, err
	}

	evt := SignedUpEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}
	return evt, nil
}

func OnSignedUp(evt SignedUpEvent, userById UserById, userIdByEmail UserIdByEmail) error {
	user := evt.Data
	userById[user.Id] = user
	userIdByEmail[user.Email] = user.Id
	return nil
}

func SignIn(appId, email, password string, userById UserById, userIdByEmail UserIdByEmail) (SignedInEvent, error) {
	userId := userIdByEmail[email]
	user := userById[userId]
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	evt := SignedInEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   AuthToken{UserId: userId, CreatedAt: time.Now()},
	}
	return evt, nil
}

func CreateJWT(authToken AuthToken) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["userId"] = authToken.UserId
	token.Claims["createdAt"] = authToken.CreatedAt.Unix()
	tokenStr, err := token.SignedString([]byte(JWT_KEY))
	if err != nil {
		log.Fatalln("[SignIn] couldn't create jwt", err)
	}
	return tokenStr
}

func ParseJWT(tokenStr string) (AuthToken, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_KEY), nil
	})
	if err != nil {
		return AuthToken{}, err
	}
	if !token.Valid {
		return AuthToken{}, ErrAuthTokenNotValid
	}

	userId := token.Claims["userId"].(string)
	createdAt := time.Unix(int64(token.Claims["createdAt"].(float64)), 0)
	return AuthToken{UserId: userId, CreatedAt: createdAt}, nil
}
