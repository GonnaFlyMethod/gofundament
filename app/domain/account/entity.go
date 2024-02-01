package account

import (
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Entity struct {
	id             string
	firstName      string
	lastName       string
	nickname       string
	email          string
	birthDate      time.Time
	currentCountry string
	createdAt      time.Time
	updatedAt      time.Time
}

func NewEntity(nickname, email string) (*Entity, error) {
	generatedUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	timestamp := time.Now()
	return &Entity{
		id:        generatedUUID.String(),
		nickname:  nickname,
		email:     email,
		createdAt: timestamp,
		updatedAt: timestamp,
	}, nil
}

func (e *Entity) GetID() string {
	return e.id
}

func (e *Entity) SetBirthDate(val time.Time) {
	e.birthDate = val
}

func (e *Entity) GetFirstName() string {
	return e.firstName
}

func (e *Entity) GetLastName() string {
	return e.lastName
}

func (e *Entity) GetNickname() string {
	return e.nickname
}

func (e *Entity) GetEmail() string {
	return e.email
}

func (e *Entity) SetFirstName(val string) {
	e.firstName = val
}

func (e *Entity) SetLastName(val string) {
	e.lastName = val
}

func (e *Entity) SetCurrentCountry(val string) {
	e.currentCountry = val
}

func (e *Entity) GetBirthDate() time.Time {
	return e.birthDate
}

func (e *Entity) GetCurrentCountry() string {
	return e.currentCountry
}

func (e *Entity) RegisterUpdate() {
	e.updatedAt = time.Now()
}

type Session struct {
	id        string
	accountID string
}

func NewSession(accountID string) (*Session, error) {
	sessionID, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while generating new token key")
	}

	return &Session{
		id:        sessionID.String(),
		accountID: accountID,
	}, nil
}

func (s *Session) GetSessionID() string {
	return s.id
}
