package account

// TODO: Observe public funcs that return private structs
// Perform multiple parallel requests to different handlers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/mojocn/base64Captcha"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest/auth"
)

type emailManager interface {
	SendVerifCodeForSignUp(emailOfReceiver, nickname, code string)
	SendVerifCodeForPasswordUpdate(emailOfReceiver, code string)
	SendVerifCodeForPasswordReset(emailOfReceiver, code string)
	SendVerifCodeToCleanSessions(emailOfReceiver, code string)

	SendPasswordUpdateNotification(emailOfReceiver string, feelLikeGetHacked bool)
	SendPasswordResetNotification(emailOfReceiver string)
}

const (
	operationSignUp           = 1
	operationPasswordUpdate   = 2
	operationPasswordReset    = 3
	operationCleaningSessions = 4
)

type Service struct {
	emailManager      emailManager
	accountRepository *accountRepository
	sessionRepository *sessionRepository
	accountSessionTxn *accountSessionTxn
	inMemoryStorage   *generalInMemoryStorage
}

func NewService(
	emailManager emailManager,
	accountRepository *accountRepository,
	sessionRepository *sessionRepository,
	accountSessionTxn *accountSessionTxn,
	inMemoryStorage *generalInMemoryStorage,
) *Service {
	return &Service{
		emailManager:      emailManager,
		accountRepository: accountRepository,
		sessionRepository: sessionRepository,
		accountSessionTxn: accountSessionTxn,
		inMemoryStorage:   inMemoryStorage,
	}
}

func (s *Service) GenerateCaptcha(ctx context.Context, captchaType int) (string, string, error) { //nolint:gocritic
	var driver base64Captcha.Driver

	switch captchaType {
	case 1:
		driver = base64Captcha.DefaultDriverDigit
	case 2:
		driver = base64Captcha.DefaultDriverAudio
	}

	captchaID, content, correctAnswer := driver.GenerateIdQuestionAnswer()

	item, err := driver.DrawCaptcha(content)
	if err != nil {
		return "", "", err
	}

	if err := s.inMemoryStorage.SetCaptchaAnswer(ctx, captchaID, correctAnswer); err != nil {
		return "", "", err
	}

	captcha := item.EncodeB64string()

	return captchaID, captcha, nil
}

type signingUpUser struct {
	email             string
	nickname          string
	encryptedPassword []byte
}

func (s *Service) StartSignUpPipe(ctx context.Context, dto *StartSignUpPipeDTO) (string, error) {
	correctCaptchaAnswer, err := s.inMemoryStorage.ReadCaptchaAnswer(ctx, dto.CaptchaID)
	if err != nil {
		return "", err
	}

	if dto.ProvidedCaptchaAnswer != correctCaptchaAnswer {
		if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
			return "", err
		}

		return "", common.NewClientSideError("provided captcha answer is invalid")
	}

	if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
		return "", err
	}

	errChan := make(chan error, 2)

	go func() {
		usersCount, err := s.accountRepository.CountUsersWithEmailOrNickname(ctx, dto.Email, dto.Nickname)
		if err != nil {
			errChan <- err

			return
		}

		if usersCount > 0 {
			errChan <- common.NewClientSideError("user with such email/nickname exists")
			return
		}

		errChan <- nil
	}()

	go func() {
		err := s.inMemoryStorage.DropErrIfNicknameReserved(ctx, dto.Nickname)
		if err != nil {
			errChan <- err

			return
		}

		errChan <- nil
	}()

	errorDescription := ""
	counter := 0

	for i := 0; i < 2; i++ {
		err := <-errChan
		if err != nil {
			errorDescription += fmt.Sprintf("%d) %s; ", counter+1, err.Error())
			counter++
		}
	}

	if errorDescription != "" {
		return "", common.NewClientSideError(errorDescription)
	}

	if err := s.inMemoryStorage.ReserveNickname(ctx, dto.Nickname); err != nil {
		return "", err
	}

	encryptedPassword, err := encryptUserPassword(dto.Password)
	if err != nil {
		return "", err
	}

	signingUpUsr := &signingUpUser{
		email:             dto.Email,
		nickname:          dto.Nickname,
		encryptedPassword: encryptedPassword,
	}

	pipeID, err := uuid.NewRandom()
	if err != nil {
		err = errors.Wrap(err, "error occurred while generating uuid")
		return "", err
	}

	pipeIDAsStr := pipeID.String()

	if err := s.inMemoryStorage.InitSigningUpUser(ctx, pipeIDAsStr, signingUpUsr); err != nil {
		return "", err
	}

	verifCode, err := generateVerificationCode()
	if err != nil {
		return "", err
	}

	err = s.inMemoryStorage.InitVerifCodePool(ctx, operationSignUp, pipeIDAsStr, verifCode)
	if err != nil {
		return "", err
	}

	go s.emailManager.SendVerifCodeForSignUp(dto.Email, dto.Nickname, verifCode)

	return pipeIDAsStr, nil
}

func (s *Service) ResendVerifCodeForSignUp(ctx context.Context, pipeID string) error {
	isTimeout, err := s.inMemoryStorage.IsTimeoutForEmailCode(ctx, operationSignUp, pipeID)
	if err != nil {
		return err
	}

	if isTimeout {
		return common.NewClientSideError("timeout for sending verification code (sign up)")
	}

	doesPoolExist, err := s.inMemoryStorage.DoesVerifCodePoolExist(ctx, operationSignUp, pipeID)
	if err != nil {
		return err
	}

	if !doesPoolExist {
		return common.NewClientSideError("the process of sign up hasn't started yet")
	}

	err = s.inMemoryStorage.SetTimeoutForEmailCode(ctx, operationSignUp, pipeID)
	if err != nil {
		return err
	}

	verifCode, err := generateVerificationCode()
	if err != nil {
		return err
	}

	if err := s.inMemoryStorage.AddVerifCodeToPool(ctx, operationSignUp, pipeID, verifCode); err != nil {
		return err
	}

	signingUpUsr, err := s.inMemoryStorage.ReadSigningUpUser(ctx, pipeID)
	if err != nil {
		return err
	}

	go s.emailManager.SendVerifCodeForSignUp(signingUpUsr.email, signingUpUsr.nickname, verifCode)

	return nil
}

func generateVerificationCode() (string, error) {
	finalResult := ""

	for i := 0; i < 6; i++ {
		randomInt, err := common.RandomIntegerSecure(0, 9)
		if err != nil {
			return "", err
		}

		partOfResult := strconv.Itoa(randomInt)
		finalResult += partOfResult
	}

	return finalResult, nil
}

func (s *Service) SignUp(ctx context.Context, dto *SignUpDTO) error {
	isMember, err := s.inMemoryStorage.IsMemberOfVerifCodePool(
		ctx, operationSignUp, dto.PipeID, dto.ProvidedVerifCode)
	if err != nil {
		return err
	}

	if !isMember {
		return common.NewClientSideError("invalid verification code")
	}

	signingUpUsr, err := s.inMemoryStorage.ReadSigningUpUser(ctx, dto.PipeID)
	if err != nil {
		return err
	}

	newEntity, err := NewEntity(signingUpUsr.nickname, signingUpUsr.email)
	if err != nil {
		return errors.Wrap(err, "failed to create account entity")
	}

	if err := s.accountRepository.CreateNew(ctx, newEntity, signingUpUsr.encryptedPassword); err != nil {
		return err
	}

	if err := s.inMemoryStorage.DeleteReservedNickname(ctx, newEntity.nickname); err != nil {
		return err
	}

	err = s.inMemoryStorage.DeleteVerifCodePool(ctx, operationSignUp, dto.PipeID)
	if err != nil {
		return err
	}

	err = s.inMemoryStorage.DeleteTimeoutForEmailCode(ctx, operationSignUp, dto.PipeID)
	if err != nil {
		return err
	}

	return s.inMemoryStorage.DeleteSigningUpUser(ctx, dto.PipeID)
}

func encryptUserPassword(plainPassword string) ([]byte, error) {
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), 12)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash password")
	}

	return encryptedPassword, nil
}

// E - email;
// E(n) == E(n + 1) - the same email between attempts to sign in;
// E(n) != E(n + 1) - different emails between attempts to sign in;
// -> - consequence;
// A - attempts to sign in with incorrect credentials;
// A * 3 - 3 attempts to sign in with incorrect credentials;

// Rules for a particular account(cycle):
// 1) A * 3, E(n) == E(n + 1) -> captcha(By account(if ip will be changed captcha should be expected anyway)).
// During sign in, captcha will be asked for 1 day (24 hours) till it will be provided
// 2) A * 6, E(n) == E(n + 1) -> sign in ban into a particular account for 30-40 min(by IP)

// Rule for different accounts:
// 1) A * 6, E(n) != E(n + 1) -> global ban for signing in for 15-20 min (by IP);

// Multiple limitations for sign in can be gotten

// For protection against targeting of a particular account the size of cycle for limitations is 6:
// |_ _ (captcha by account)_ _ (account ban by ip)|...(repeat)
// This is true for the case when the access to a particular account is performed by the same client.
// If multiple clients try to get access to the same account simultaneously, one of them can see captcha earlier:
// client  | _ _ (captcha by account)
// client1 |                          (captcha by account) ...

// For protection against targeting of a particular account there's a strict order of limitations:
// 1) Captcha
// 2) Account ban
// This order should not be changed and should meet the following constraint:
// attemptsInCycleToGetCaptcha < attemptsInCycleToGetAccountBan

const (
	attemptsToGetGlobalBan = 6

	attemptsInCycleToGetCaptcha  = 3
	captchaIntervalNormalization = 3

	attemptsInCycleToGetAccountBan = 6
)

const maxNumOfSessionsPerAccount = 100

//nolint:gocyclo,nestif,maintidx
func (s *Service) SignIn(ctx context.Context, dto *SignInDTO, keyReader auth.KeyReader) (*SignInResultDTO, error) {
	gotGlobalBan, err := s.inMemoryStorage.IsSignInGlobalBan(ctx, dto.IP)
	if err != nil {
		return nil, err
	}

	if gotGlobalBan {
		return nil, common.NewClientSideError("Global ban for sign in")
	}

	entity, encryptedPassword, err := s.accountRepository.ReadByEmailWithEncryptedPass(ctx, dto.Email)
	if err != nil {
		var cse *common.ClientSideError

		if errors.Is(err, cse) {
			return nil, common.NewClientSideError("Invalid credentials")
		}

		return nil, err
	}

	gotAccountBan, err := s.inMemoryStorage.IsSignInAccountBan(ctx, dto.IP, entity.id)
	if err != nil {
		return nil, err
	}

	if gotAccountBan {
		return nil, common.NewClientSideError("Account ban for sign in")
	}

	// Captcha
	gotCaptcha, err := s.inMemoryStorage.IsSignInCaptcha(ctx, entity.id)
	if err != nil {
		return nil, err
	}

	if gotCaptcha {
		correctCaptchaAnswer, err := s.inMemoryStorage.ReadCaptchaAnswer(ctx, dto.CaptchaID)
		if err != nil {
			return nil, err
		}

		if dto.ProvidedCaptchaAnswer != correctCaptchaAnswer {
			if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
				return nil, err
			}

			return nil, common.NewClientSideError("provided captcha answer is invalid")
		}

		if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
			return nil, err
		}

		if err := s.inMemoryStorage.DeleteSignInCaptchaLimit(ctx, entity.id); err != nil {
			return nil, err
		}
	}

	// Auth
	if err = bcrypt.CompareHashAndPassword(encryptedPassword, []byte(dto.Password)); err != nil {
		// Preventing password cracking brute-force attack

		doesExist, err := s.inMemoryStorage.DoesCaptchaTrackerExist(ctx, entity.id)
		if err != nil {
			return nil, err
		}

		if !doesExist {
			if err := s.inMemoryStorage.InitCaptchaTracker(ctx, entity.id, 0); err != nil {
				return nil, err
			}
		}

		doesExist, err = s.inMemoryStorage.DoesGlobalBanTrackerExist(ctx, dto.IP)
		if err != nil {
			return nil, err
		}

		if !doesExist {
			if err := s.inMemoryStorage.InitGlobalBanTracker(ctx, dto.IP, entity.id); err != nil {
				return nil, err
			}
		}

		doesExist, err = s.inMemoryStorage.DoesAccountBanTrackerExist(ctx, dto.IP, entity.id)
		if err != nil {
			return nil, err
		}

		if !doesExist {
			if err := s.inMemoryStorage.InitAccountBanTracker(ctx, dto.IP, entity.id, 0); err != nil {
				return nil, err
			}
		}

		err = s.inMemoryStorage.UpdateTrackersForSignIn(ctx, dto.IP, entity.id)
		if err != nil {
			return nil, err
		}

		captchaTracker, err := s.inMemoryStorage.ReadCaptchaTracker(ctx, entity.id)
		if err != nil {
			return nil, err
		}

		globalBanTracker, err := s.inMemoryStorage.ReadGlobalBanTracker(ctx, dto.IP)
		if err != nil {
			return nil, err
		}

		accountBanTracker, err := s.inMemoryStorage.ReadAccountBanTracker(ctx, dto.IP, entity.id)
		if err != nil {
			return nil, err
		}

		if captchaTracker == attemptsInCycleToGetCaptcha {
			err := s.inMemoryStorage.SetCaptchaLimitAndResetCaptchaTracker(ctx, entity.id, -captchaIntervalNormalization)
			if err != nil {
				return nil, err
			}

			return nil, common.NewClientSideError("Invalid credentials")
		}

		if len(globalBanTracker) == attemptsToGetGlobalBan {
			if err := s.inMemoryStorage.SetGlobalBanAndDelGlobalBanTracker(ctx, dto.IP); err != nil {
				return nil, err
			}

			return nil, common.NewClientSideError("Global sign in ban for a period of time")
		}

		if accountBanTracker == attemptsInCycleToGetAccountBan {
			if err := s.inMemoryStorage.SetAccountBanAndDelAccountBanTracker(ctx, dto.IP, entity.id); err != nil {
				return nil, err
			}

			return nil, common.NewClientSideError("Account sign in ban for a period of time")
		}

		return nil, common.NewClientSideError("Invalid credentials")
	}

	// Preventing sessions overflow for one account
	currentNumOfSessions, err := s.sessionRepository.CountNumOfSessionsByAccountID(ctx, entity.id)
	if err != nil {
		return nil, err
	}

	if (currentNumOfSessions + 1) > maxNumOfSessionsPerAccount {
		doesExist, err := s.inMemoryStorage.DoesSessionsOverflowPoolExist(ctx, dto.IP, entity.email)
		if err != nil {
			return nil, err
		}

		var pipeIDToReturn string

		switch {
		case doesExist:
			pipeIDToReturn, err = s.inMemoryStorage.ReadSessionsOverflowStatus(ctx, dto.IP, entity.email)
			if err != nil {
				return nil, err
			}

		default:
			pipeID, err := uuid.NewRandom()
			if err != nil {
				err = errors.Wrap(err, "error occurred while generating uuid")
				return nil, err
			}

			pipeIDAsStr := pipeID.String()

			err = s.inMemoryStorage.InitSessionsOverflowStatus(ctx, dto.IP, entity.email, pipeIDAsStr)

			if err != nil {
				return nil, err
			}

			pipeIDToReturn = pipeIDAsStr
		}

		resultDTO := &SignInResultDTO{
			AccessToken:            "",
			RefreshToken:           "",
			SessionsOverflowPipeID: pipeIDToReturn,
		}

		return resultDTO, nil
	}

	// Creating session
	session, err := NewSession(entity.id)
	if err != nil {
		return nil, err
	}

	sessionID := session.GetSessionID()

	accessToken, refreshToken, err := auth.GenerateTokensPair(entity.id, sessionID, keyReader)
	if err != nil {
		return nil, err
	}

	if err := s.sessionRepository.CreateNew(ctx, session); err != nil {
		return nil, err
	}

	resultDto := &SignInResultDTO{
		AccessToken:            accessToken,
		RefreshToken:           refreshToken,
		SessionsOverflowPipeID: "",
	}

	return resultDto, nil
}

func (s *Service) IsSignInCaptcha(ctx context.Context, email string) (bool, error) {
	entity, err := s.accountRepository.ReadByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	result, err := s.inMemoryStorage.IsSignInCaptcha(ctx, entity.id)
	if err != nil {
		return false, err
	}

	return result, nil
}

const sendEmailCodeAttemptsToGetBan = 3

// TODO:
// Give ban by IP for 30-40 min when incorrect code was provided for 3 times

// TODO:
// Universal security mechanism for resending verification codes:
// -> - sending verification code to email
// ->[TIMEOUT 1 MIN]->[TIMEOUT 1 MIN]->[BAN 30-40 MIN BY IP]

// TODO:
// consider returning TTL for email code timeout from service func

//nolint:gocyclo
func (s *Service) SendVerifCodeToCleanSessions(ctx context.Context, dto *SendVerifCodeToCleanSessionsDTO) error {
	// TODO: abstract email code security mechanism into a func to be reusable

	isBan, err := s.inMemoryStorage.IsBanForEmailCode(ctx, operationCleaningSessions, dto.Email)
	if err != nil {
		return err
	}

	if isBan {
		return common.NewClientSideError("Local ban for email code sending")
	}

	isTimeout, err := s.inMemoryStorage.IsTimeoutForEmailCode(ctx, operationCleaningSessions, dto.Email)
	if err != nil {
		return err
	}

	if isTimeout {
		return common.NewClientSideError("timeout for sending verification code (cleaning sessions)")
	}

	correctPipeID, err := s.inMemoryStorage.ReadSessionsOverflowStatus(ctx, dto.IP, dto.Email)
	if err != nil {
		return err
	}

	if correctPipeID != dto.PipeID {
		return common.NewClientSideError("Invalid input")
	}

	entity, err := s.accountRepository.ReadByEmail(ctx, dto.Email)
	if err != nil {
		var cse *common.ClientSideError

		if errors.Is(err, cse) {
			return common.NewClientSideError("Invalid input")
		}

		return err
	}

	currentNumOfSessions, err := s.sessionRepository.CountNumOfSessionsByAccountID(ctx, entity.id)
	if err != nil {
		return err
	}

	if (currentNumOfSessions + 1) <= maxNumOfSessionsPerAccount {
		return common.NewClientSideError("Incorrect usage detected")
	}

	doesExist, err := s.inMemoryStorage.DoesEmailCodeTrackerExist(ctx, operationCleaningSessions, dto.Email)
	if err != nil {
		return err
	}

	if !doesExist {
		if err := s.inMemoryStorage.InitEmailCodeTracker(ctx, operationCleaningSessions, dto.Email, 0); err != nil {
			return err
		}
	}

	if err := s.inMemoryStorage.UpdateEmailCodeTracker(ctx, operationCleaningSessions, dto.Email); err != nil {
		return err
	}

	emailCodeTracker, err := s.inMemoryStorage.ReadEmailCodeTracker(ctx, operationCleaningSessions, dto.Email)
	if err != nil {
		return err
	}

	switch {
	case emailCodeTracker == sendEmailCodeAttemptsToGetBan:
		err := s.inMemoryStorage.SetBanForEmailCodeAndDelEmailCodeTracker(ctx, operationCleaningSessions, dto.Email)

		if err != nil {
			return err
		}
	default:
		err := s.inMemoryStorage.SetTimeoutForEmailCode(ctx, operationCleaningSessions, dto.Email)

		if err != nil {
			return err
		}
	}

	verifCode, err := generateVerificationCode()
	if err != nil {
		return err
	}

	doesPoolExist, err := s.inMemoryStorage.DoesVerifCodePoolExist(ctx, operationCleaningSessions, dto.Email)
	if err != nil {
		return err
	}

	switch {
	case doesPoolExist:
		err = s.inMemoryStorage.AddVerifCodeToPool(ctx, operationCleaningSessions, dto.Email, verifCode)

		if err != nil {
			return err
		}
	default:
		err = s.inMemoryStorage.InitVerifCodePool(ctx, operationCleaningSessions, dto.Email, verifCode)

		if err != nil {
			return err
		}
	}

	go s.emailManager.SendVerifCodeToCleanSessions(dto.Email, verifCode)

	return nil
}

// HandleSessionsOverflow TODO: replace successful returning results (string, string) with dto

//nolint:gocritic
func (s *Service) HandleSessionsOverflow(ctx context.Context,
	dto *HandleSessionsOverflowDTO, keyReader auth.KeyReader) (string, string, error) {
	entity, err := s.accountRepository.ReadByEmail(ctx, dto.Email)
	if err != nil {
		var cse *common.ClientSideError

		if errors.Is(err, cse) {
			return "", "", common.NewClientSideError("Invalid input")
		}

		return "", "", err
	}

	correctPipeID, err := s.inMemoryStorage.ReadSessionsOverflowStatus(ctx, dto.IP, dto.Email)
	if err != nil {
		return "", "", err
	}

	if correctPipeID != dto.PipeID {
		return "", "", common.NewClientSideError("Invalid input")
	}

	currentNumOfSessions, err := s.sessionRepository.CountNumOfSessionsByAccountID(ctx, entity.id)
	if err != nil {
		return "", "", err
	}

	if (currentNumOfSessions + 1) <= maxNumOfSessionsPerAccount {
		return "", "", common.NewClientSideError("Incorrect usage detected")
	}

	isMember, err := s.inMemoryStorage.IsMemberOfVerifCodePool(ctx, operationCleaningSessions, dto.Email, dto.VerifCode)
	if err != nil {
		return "", "", err
	}

	if !isMember {
		return "", "", common.NewClientSideError("Incorrect verification code")
	}

	session, err := NewSession(entity.id)
	if err != nil {
		return "", "", err
	}

	sessionID := session.GetSessionID()

	accessToken, refreshToken, err := auth.GenerateTokensPair(entity.id, sessionID, keyReader)
	if err != nil {
		return "", "", err
	}

	if err := s.sessionRepository.DeleteSessionsAndCreateNew(ctx, entity.id, session); err != nil {
		return "", "", err
	}

	err = s.inMemoryStorage.DeleteVerifCodePool(ctx, operationCleaningSessions, entity.email)
	if err != nil {
		return "", "", err
	}

	if err := s.inMemoryStorage.DeleteSessionsOverflowStatus(ctx, dto.IP, entity.email); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string, keyReader auth.KeyReader) error {
	_, sessionID, err := auth.ValidateRefreshToken(refreshToken, keyReader)
	if err != nil {
		return err
	}

	return s.sessionRepository.DeleteSession(ctx, sessionID)
}

func (s *Service) GetAccessToken(ctx context.Context, refreshToken string, keyReader auth.KeyReader) (string, error) {
	accountID, sessionID, err := auth.ValidateRefreshToken(refreshToken, keyReader)
	if err != nil {
		return "", err
	}

	numberOfSessions, err := s.sessionRepository.CountNumOfSessionsBySessID(ctx, sessionID)
	if err != nil {
		return "", err
	}

	if numberOfSessions == 0 {
		return "", common.NewClientSideError("Invalid refresh token")
	}

	accessToken, err := auth.GenerateAccessToken(accountID, keyReader)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// CreatePasswordResetRequest TODO: implement security mechanism
// -> - Sending verif code
// ->->->[Ban for 30 min BY IP]
func (s *Service) CreatePasswordResetRequest(ctx context.Context, dto *PasswordResetRequestDTO) error {
	result, err := s.accountRepository.CountUsersWithEmail(ctx, dto.Email)
	if err != nil {
		return err
	}

	if result == 0 {
		errMsg := "the provided email is not associated with a personal user account"
		return common.NewClientSideError(errMsg)
	}

	correctCaptchaAnswer, err := s.inMemoryStorage.ReadCaptchaAnswer(ctx, dto.CaptchaID)
	if err != nil {
		return err
	}

	if dto.ProvidedCaptchaAnswer != correctCaptchaAnswer {
		if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
			return err
		}

		return common.NewClientSideError("provided captcha answer is invalid")
	}

	if err := s.inMemoryStorage.DeleteCaptchaAnswer(ctx, dto.CaptchaID); err != nil {
		return err
	}

	verifCode, err := generateVerificationCode()
	if err != nil {
		return err
	}

	doesPoolExist, err := s.inMemoryStorage.DoesVerifCodePoolExist(ctx, operationPasswordReset, dto.Email)
	if err != nil {
		return err
	}

	switch {
	case doesPoolExist:
		err := s.inMemoryStorage.AddVerifCodeToPool(ctx, operationPasswordReset, dto.Email, verifCode)
		if err != nil {
			return err
		}
	default:
		err := s.inMemoryStorage.InitVerifCodePool(ctx, operationPasswordReset, dto.Email, verifCode)
		if err != nil {
			return err
		}
	}

	// TODO: inject code into jwt and send it as a link to user

	go s.emailManager.SendVerifCodeForPasswordReset(dto.Email, verifCode)

	return nil
}

func (s *Service) PerformPasswordReset(ctx context.Context, dto *PerformPasswordResetDTO) error {
	// TODO first of all, check whether there's a ban for password reset request
	// TODO: then get code from JWT

	isMember, err := s.inMemoryStorage.IsMemberOfVerifCodePool(
		ctx, operationPasswordReset, dto.Email, dto.VerifCode)
	if err != nil {
		return err
	}

	if !isMember {
		return common.NewClientSideError("invalid verification code")
	}

	entity, err := s.accountRepository.ReadByEmail(ctx, dto.Email)
	if err != nil {
		return err
	}

	encryptedNewPassword, err := encryptUserPassword(dto.NewPassword)
	if err != nil {
		return err
	}

	entity.RegisterUpdate()

	if err := s.accountRepository.UpdatePassword(ctx, entity, encryptedNewPassword); err != nil {
		return err
	}

	go s.emailManager.SendPasswordResetNotification(dto.Email)

	return s.inMemoryStorage.DeleteVerifCodePool(ctx, operationPasswordReset, dto.Email)
}

func (s *Service) SendVerifCodeForPasswordUpdate(ctx context.Context, accountID string) error {
	// TODO: add captcha before sending verification code

	entity, err := s.accountRepository.ReadByID(ctx, accountID)
	if err != nil {
		return err
	}

	verifCode, err := generateVerificationCode()
	if err != nil {
		return err
	}

	doesPoolExist, err := s.inMemoryStorage.DoesVerifCodePoolExist(ctx, operationPasswordUpdate, entity.email)
	if err != nil {
		return err
	}

	switch {
	case doesPoolExist:
		err := s.inMemoryStorage.AddVerifCodeToPool(ctx, operationPasswordUpdate, entity.email, verifCode)
		if err != nil {
			return err
		}
	default:
		err := s.inMemoryStorage.InitVerifCodePool(ctx, operationPasswordUpdate, entity.email, verifCode)
		if err != nil {
			return err
		}
	}

	go s.emailManager.SendVerifCodeForPasswordUpdate(entity.email, verifCode)

	return nil
}

func (s *Service) UpdatePassword(ctx context.Context, dto *UpdatePasswordDTO, keyReader auth.KeyReader) (string, error) {
	accountID, sessionIDToDelete, err := auth.ValidateRefreshToken(dto.RefreshToken, keyReader)
	if err != nil {
		return "", err
	}

	entity, err := s.accountRepository.ReadByID(ctx, accountID)
	if err != nil {
		return "", err
	}

	isMember, err := s.inMemoryStorage.IsMemberOfVerifCodePool(
		ctx, operationPasswordUpdate, entity.email, dto.ProvidedVerifCode)
	if err != nil {
		return "", err
	}

	if !isMember {
		return "", common.NewClientSideError("invalid verification code")
	}

	encryptedNewPassword, err := encryptUserPassword(dto.NewPassword)
	if err != nil {
		return "", err
	}

	newSession, err := NewSession(accountID)
	if err != nil {
		return "", err
	}

	entity.RegisterUpdate()

	switch {
	case dto.FeelLikeGetHacked:
		err := s.accountSessionTxn.UpdatePasswordRadical(ctx, entity, encryptedNewPassword, newSession)
		if err != nil {
			return "", err
		}
	default:
		err := s.accountSessionTxn.UpdatePassword(ctx, entity, encryptedNewPassword, newSession, sessionIDToDelete)
		if err != nil {
			return "", err
		}
	}

	newSessionID := newSession.GetSessionID()

	newRefreshToken, err := auth.GenerateRefreshToken(accountID, newSessionID, keyReader)
	if err != nil {
		return "", err
	}

	go s.emailManager.SendPasswordUpdateNotification(entity.email, dto.FeelLikeGetHacked)

	err = s.inMemoryStorage.DeleteVerifCodePool(ctx, operationPasswordUpdate, entity.email)
	if err != nil {
		return "", err
	}

	return newRefreshToken, nil
}

func (s *Service) UpdateAccount(ctx context.Context, dto *UpdateAccountDTO) error {
	existingAccount, err := s.accountRepository.ReadByID(ctx, dto.ID)
	if err != nil {
		return err
	}

	existingAccount.SetBirthDate(dto.BirthDate)
	existingAccount.SetCurrentCountry(dto.CurrentCountry)
	existingAccount.SetFirstName(dto.FirstName)
	existingAccount.SetLastName(dto.LastName)

	existingAccount.RegisterUpdate()

	if err := s.accountRepository.Update(ctx, existingAccount); err != nil {
		return err
	}

	return nil
}

func (s *Service) GetAccount(ctx context.Context, nickname string) (*Entity, error) {
	entity, err := s.accountRepository.ReadByNickname(ctx, nickname)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// IsAvailableEmail TODO: check pipeID(from sign up)
func (s *Service) IsAvailableEmail(ctx context.Context, email string) (bool, error) {
	result, err := s.accountRepository.CountUsersWithEmail(ctx, email)
	if err != nil {
		return false, err
	}

	return result == 0, nil
}

// IsAvailableNickname TODO: check pipeID(from sign up)
func (s *Service) IsAvailableNickname(ctx context.Context, nickname string) (bool, error) {
	result, err := s.accountRepository.CountUsersWithNickname(ctx, nickname)
	if err != nil {
		return false, err
	}

	return result == 0, nil
}
