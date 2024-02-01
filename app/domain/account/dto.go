package account

import (
	"time"
)

type StartSignUpPipeDTO struct {
	CaptchaID             string
	ProvidedCaptchaAnswer string
	Email                 string
	Nickname              string
	Password              string
}

type SignUpDTO struct {
	ProvidedVerifCode string
	PipeID            string
}

type PrepareSessOverflowPipeDTO struct {
	IP        string
	AccountID string
	Email     string
}

type SignInDTO struct {
	CaptchaID             string
	ProvidedCaptchaAnswer string
	Email                 string
	Password              string
	IP                    string
}

type SignInResultDTO struct {
	AccessToken            string
	RefreshToken           string
	SessionsOverflowPipeID string
}

type SendVerifCodeToCleanSessionsDTO struct {
	IP     string
	Email  string
	PipeID string
}

type HandleSessionsOverflowDTO struct {
	Email     string
	VerifCode string
	IP        string
	PipeID    string
}

type PasswordResetRequestDTO struct {
	CaptchaID             string
	ProvidedCaptchaAnswer string
	Email                 string
}

type PerformPasswordResetDTO struct {
	VerifCode   string
	Email       string
	NewPassword string
}

type UpdatePasswordDTO struct {
	RefreshToken      string
	NewPassword       string
	FeelLikeGetHacked bool
	ProvidedVerifCode string
}

type UpdateAccountDTO struct {
	ID             string
	BirthDate      time.Time
	CurrentCountry string
	FirstName      string
	LastName       string
}
