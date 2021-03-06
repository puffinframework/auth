package auth

import (
	"time"
)

type User struct {
	Id             string
	AppId          string
	Email          string
	HashedPassword []byte
}

type Session struct {
	UserId    string
	CreatedAt time.Time
}

type Verification struct {
	UserId string
	Email  string
}

type Reset struct {
	UserId    string
	Email     string
	CreatedAt time.Time
}
