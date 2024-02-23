package account

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest/auth"
)

func TestService_RegistrationFlow(t *testing.T) {
	t.Run("correct captcha answer provided", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		service := getTestService()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		redisClient := common.GetTestRedisClient()

		redisKeyForCaptcha := fmt.Sprintf(captchaKey, captchaID)

		correctCaptchaAnswer, err := redisClient.Get(ctx, redisKeyForCaptcha).Result()
		assert.NoError(t, err)

		startSignUpPipeDto := &StartSignUpPipeDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 "test.email@domain.com",
			Nickname:              "test_nickname",
			Password:              "test_password123",
		}

		pipeID, err := service.StartSignUpPipe(ctx, startSignUpPipeDto)
		assert.NoError(t, err)
		assert.NotEmpty(t, pipeID)
	})

	t.Run("incorrect captcha answer provided", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		service := getTestService()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		redisClient := common.GetTestRedisClient()

		redisKeyForCaptcha := fmt.Sprintf(captchaKey, captchaID)

		correctCaptchaAnswer, err := redisClient.Get(ctx, redisKeyForCaptcha).Result()
		assert.NoError(t, err)

		startSignUpPipeDto := &StartSignUpPipeDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: common.ReverseString(correctCaptchaAnswer),
			Email:                 "test.email@domain.com",
			Nickname:              "test_nickname",
			Password:              "test_password123",
		}

		pipeID, err := service.StartSignUpPipe(ctx, startSignUpPipeDto)
		common.AssertClientSideError(t, err)
		assert.Empty(t, pipeID)

		assertInMemoryStorageIsCleaned(ctx, t)
	})

	t.Run("complete sign up pipeline", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		service, emailManagerMock := getTestServiceAndEmailManager()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		correctCaptchaAnswer := readCaptchaAnswer(ctx, t, captchaID)
		assert.NoError(t, err)

		const emailOfUserInTest = "test.email@domain.com"

		startSignUpPipeDto := &StartSignUpPipeDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 emailOfUserInTest,
			Nickname:              "test_nickname",
			Password:              "test_password123",
		}

		pipeID, err := service.StartSignUpPipe(ctx, startSignUpPipeDto)
		assert.NoError(t, err)

		err = service.ResendVerifCodeForSignUp(ctx, pipeID)
		assert.NoError(t, err)

		err = service.ResendVerifCodeForSignUp(ctx, pipeID)
		common.AssertClientSideError(t, err)

		verifCode := emailManagerMock.ReadInbox(ctx, t, emailOfUserInTest)

		signUPDto := &SignUpDTO{
			ProvidedVerifCode: verifCode,
			PipeID:            pipeID,
		}

		err = service.SignUp(ctx, signUPDto)
		assert.NoError(t, err)

		actualEntities := readTestAccounts(ctx, t)
		assert.Len(t, actualEntities, 1)

		assertInMemoryStorageIsCleaned(ctx, t)
	})

	t.Run("incorrect verification code", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		service, emailManagerMock := getTestServiceAndEmailManager()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		redisClient := common.GetTestRedisClient()

		redisKeyForCaptcha := fmt.Sprintf(captchaKey, captchaID)

		correctCaptchaAnswer, err := redisClient.Get(ctx, redisKeyForCaptcha).Result()
		assert.NoError(t, err)

		const emailOfUserInTest = "test.email@domain.com"

		startSignUpPipeDto := &StartSignUpPipeDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 emailOfUserInTest,
			Nickname:              "test_nickname",
			Password:              "test_password123",
		}

		pipeID, err := service.StartSignUpPipe(ctx, startSignUpPipeDto)
		assert.NoError(t, err)

		verifCode := emailManagerMock.ReadInbox(ctx, t, emailOfUserInTest)

		signUPDto := &SignUpDTO{
			ProvidedVerifCode: common.ReverseString(verifCode),
			PipeID:            pipeID,
		}

		err = service.SignUp(ctx, signUPDto)
		common.AssertClientSideError(t, err)

		actualEntities := readTestAccounts(ctx, t)
		assert.Len(t, actualEntities, 0)
	})

	t.Run("preventing sign up flow because of reserved nickname and existing nickname with email", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		const (
			existingEmailInTest    = "existing.email@domain.com"
			existingNicknameInTest = "existing_nickname"
		)

		entity := getTestEntity(t)

		entity.email = existingEmailInTest
		entity.nickname = existingNicknameInTest

		createTestAccount(ctx, t, entity, "test_password")

		service := getTestService()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		redisClient := common.GetTestRedisClient()

		redisKeyForCaptcha := fmt.Sprintf(captchaKey, captchaID)

		correctCaptchaAnswer, err := redisClient.Get(ctx, redisKeyForCaptcha).Result()
		assert.NoError(t, err)

		const reservedNicknameInTest = "reserved_nickname"

		startSignUpPipeDto := &StartSignUpPipeDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 "test.email@domain.com",
			Nickname:              reservedNicknameInTest,
			Password:              "test_password123",
		}

		_, err = service.StartSignUpPipe(ctx, startSignUpPipeDto)
		assert.NoError(t, err)

		testCases := []struct {
			name     string
			email    string
			nickname string
		}{
			{
				name: "should get error because of reserved nickname",

				email:    "valid.new.email@domain.com",
				nickname: reservedNicknameInTest,
			},
			{
				name: "should get error because of existing nickname",

				email:    "valid.new.email@domain.com",
				nickname: existingNicknameInTest,
			},
			{
				name: "should get error because of existing email",

				email:    existingEmailInTest,
				nickname: "new_valid_nickname",
			},
			{
				name: "should get error because of reserved nickname and existing email",

				email:    existingEmailInTest,
				nickname: reservedNicknameInTest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				captchaIDOfCurrentUser, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
				assert.NoError(t, err)

				captchaAnswerOfCurUser := readCaptchaAnswer(ctx, t, captchaIDOfCurrentUser)

				startSignUpPipeDtoCurUsr := &StartSignUpPipeDTO{
					CaptchaID:             captchaIDOfCurrentUser,
					ProvidedCaptchaAnswer: captchaAnswerOfCurUser,
					Email:                 tc.email,
					Nickname:              tc.nickname,
					Password:              "test_password123",
				}

				_, err = service.StartSignUpPipe(ctx, startSignUpPipeDtoCurUsr)
				common.AssertClientSideError(t, err)
			})
		}
	})
}

func TestService_SignInWithSessionsOverflow(t *testing.T) {
	t.Run("testing successful handling of sessions' overflow", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		entity := getTestEntity(t)

		const accountPassword = "test_password123"
		createTestAccount(ctx, t, entity, accountPassword)

		service, emailManagerMock := getTestServiceAndEmailManager()

		const ipOfClient = "83.131.23.200"

		signInDTO := &SignInDTO{
			Email:    entity.email,
			Password: accountPassword,
			IP:       ipOfClient,
		}

		keyReader := auth.MockKeyReader{}

		for i := 0; i < maxNumOfSessionsPerAccount; i++ {
			resultDTO, err := service.SignIn(ctx, signInDTO, keyReader)

			assert.NotEmpty(t, resultDTO.AccessToken)
			assert.NotEmpty(t, resultDTO.RefreshToken)
			assert.Empty(t, resultDTO.SessionsOverflowPipeID)
			assert.NoError(t, err)
		}

		resultDTO, err := service.SignIn(ctx, signInDTO, keyReader)
		sessionsOverflowPipeID := resultDTO.SessionsOverflowPipeID

		assert.NoError(t, err)

		assert.Empty(t, resultDTO.AccessToken)
		assert.Empty(t, resultDTO.RefreshToken)
		assert.NotEmpty(t, sessionsOverflowPipeID)

		sendCodeToCleanSessionsDTO := &SendVerifCodeToCleanSessionsDTO{
			IP:     ipOfClient,
			Email:  entity.email,
			PipeID: sessionsOverflowPipeID,
		}

		err = service.SendVerifCodeToCleanSessions(ctx, sendCodeToCleanSessionsDTO)
		assert.NoError(t, err)

		verifCode := emailManagerMock.ReadInbox(ctx, t, entity.email)

		numOfSessionsBeforeCleaning := countSessions(ctx, t, entity.id)
		assert.Equal(t, maxNumOfSessionsPerAccount, numOfSessionsBeforeCleaning)

		handleOverflowDTO := &HandleSessionsOverflowDTO{
			Email:     entity.email,
			VerifCode: verifCode,
			IP:        ipOfClient,
			PipeID:    sessionsOverflowPipeID,
		}

		accessToken, refreshToken, err := service.HandleSessionsOverflow(ctx, handleOverflowDTO, keyReader)
		assert.NoError(t, err)

		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)

		numOfSessionsAfterCleaning := countSessions(ctx, t, entity.id)
		assert.Equal(t, 1, numOfSessionsAfterCleaning)
	})

	t.Run("testing logical gap between handlers while handling sessions' overflow", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		entity := getTestEntity(t)

		const accountPassword = "test_password123"
		createTestAccount(ctx, t, entity, accountPassword)

		service, emailManagerMock := getTestServiceAndEmailManager()

		const (
			correctIPOfClient   = "83.131.23.200"
			incorrectIPOfClient = "55.135.132.81"
		)

		signInDTO := &SignInDTO{
			Email:    entity.email,
			Password: accountPassword,
			IP:       correctIPOfClient,
		}

		keyReader := auth.MockKeyReader{}

		for i := 0; i < maxNumOfSessionsPerAccount; i++ {
			_, err := service.SignIn(ctx, signInDTO, keyReader)
			assert.NoError(t, err)
		}

		resultDTO, err := service.SignIn(ctx, signInDTO, keyReader)
		assert.NoError(t, err)

		sessionsOverflowPipeID := resultDTO.SessionsOverflowPipeID
		const incorrectPipeID = "435005f3-e25f-4feb-b0bc-e5597a62cabb"

		// logical errors for the section that is responsible for sending verification code
		sendCodeToCleanSessionsDTO := &SendVerifCodeToCleanSessionsDTO{
			IP: incorrectIPOfClient, Email: entity.email, PipeID: sessionsOverflowPipeID,
		}

		err = service.SendVerifCodeToCleanSessions(ctx, sendCodeToCleanSessionsDTO)
		common.AssertClientSideError(t, err)

		sendCodeToCleanSessionsDTO = &SendVerifCodeToCleanSessionsDTO{
			IP: correctIPOfClient, Email: entity.email, PipeID: incorrectPipeID,
		}

		err = service.SendVerifCodeToCleanSessions(ctx, sendCodeToCleanSessionsDTO)
		common.AssertClientSideError(t, err)

		sendCodeToCleanSessionsDTO = &SendVerifCodeToCleanSessionsDTO{
			IP: correctIPOfClient, Email: entity.email, PipeID: sessionsOverflowPipeID}

		err = service.SendVerifCodeToCleanSessions(ctx, sendCodeToCleanSessionsDTO)
		assert.NoError(t, err)

		verifCode := emailManagerMock.ReadInbox(ctx, t, entity.email)

		// logical errors for the section that is responsible for handling sessions' overflow
		handleOverflowDTO := &HandleSessionsOverflowDTO{
			Email:     entity.email,
			VerifCode: verifCode,
			IP:        incorrectIPOfClient,
			PipeID:    sessionsOverflowPipeID,
		}

		accessToken, refreshToken, err := service.HandleSessionsOverflow(ctx, handleOverflowDTO, keyReader)
		common.AssertClientSideError(t, err)

		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)

		handleOverflowDTO = &HandleSessionsOverflowDTO{
			Email:     entity.email,
			VerifCode: verifCode,
			IP:        correctIPOfClient,
			PipeID:    incorrectPipeID,
		}

		accessToken, refreshToken, err = service.HandleSessionsOverflow(ctx, handleOverflowDTO, keyReader)
		common.AssertClientSideError(t, err)

		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})
}

func TestService_SignInWithPasswordCracking(t *testing.T) {
	t.Run("test protection against global targeting", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		const accountPassword = "test_password123"

		var accountsEmails []string

		for i := 0; i < attemptsToGetGlobalBan; i++ {
			entity := getTestEntity(t)

			entity.email = fmt.Sprintf("test%d@domain.com", i)
			entity.nickname = fmt.Sprintf("test_nickname%d", i)

			createTestAccount(ctx, t, entity, accountPassword)

			accountsEmails = append(accountsEmails, entity.email)
		}

		service := getTestService()

		keyReader := auth.MockKeyReader{}

		ipOfClient := "83.131.23.200"

		for _, email := range accountsEmails {
			dto := &SignInDTO{
				Email:    email,
				Password: common.ReverseString(accountPassword),
				IP:       ipOfClient,
			}

			resultDTO, err := service.SignIn(ctx, dto, keyReader)

			assert.Nil(t, resultDTO)
			common.AssertClientSideError(t, err)
		}

		globalBanState := isGlobalBanForSignIn(ctx, t, ipOfClient)
		assert.True(t, globalBanState)

		for _, email := range accountsEmails {
			accountBanState := isAccountBanForSignIn(ctx, t, ipOfClient, email)
			assert.False(t, accountBanState)
		}
	})

	t.Run("test protection against targeting of a particular account", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		service := getTestService()

		entity := getTestEntity(t)
		const accountPassword = "test_password123"

		createTestAccount(ctx, t, entity, accountPassword)

		dto := &SignInDTO{
			Email:    entity.email,
			Password: common.ReverseString(accountPassword),
			IP:       "83.131.23.200",
		}

		keyReader := auth.MockKeyReader{}

		for i := 1; i <= attemptsInCycleToGetAccountBan; i++ {
			actualCaptchaStatus, err := service.IsSignInCaptcha(ctx, entity.email)
			assert.NoError(t, err)

			switch {
			case i == attemptsInCycleToGetCaptcha+1:
				assert.True(t, actualCaptchaStatus)

				const captchaImage = 1

				captchaID, _, err := service.GenerateCaptcha(ctx, captchaImage)
				assert.NoError(t, err)

				correctCaptchaAnswer := readCaptchaAnswer(ctx, t, captchaID)

				dto.CaptchaID = captchaID
				dto.ProvidedCaptchaAnswer = correctCaptchaAnswer
			default:
				assert.False(t, actualCaptchaStatus)
			}

			resultDTO, err := service.SignIn(ctx, dto, keyReader)
			assert.Nil(t, resultDTO)

			common.AssertClientSideError(t, err)
		}

		globalBanState := isGlobalBanForSignIn(ctx, t, dto.IP)
		assert.False(t, globalBanState)

		accountBanState := isAccountBanForSignIn(ctx, t, dto.IP, entity.id)
		assert.True(t, accountBanState)
	})
}

func TestService_UpdatePasswordFlow(t *testing.T) {
	t.Run("updating password when 'feel like get hacked' is false", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestDB(ctx, t)
		common.ClearTestRedis(ctx)

		entity := getTestEntity(t)

		const accountCurrentPassword = "test_password123"
		createTestAccount(ctx, t, entity, accountCurrentPassword)

		var refreshTokens []string
		keyReader := auth.MockKeyReader{}

		for i := 0; i < 4; i++ {
			generatedUUID, err := uuid.NewRandom()
			assert.NoError(t, err)

			session := &Session{
				id:        generatedUUID.String(),
				accountID: entity.id,
			}

			createSession(ctx, t, session)

			refreshToken, err := auth.GenerateRefreshToken(entity.id, session.id, keyReader)
			assert.NoError(t, err)

			refreshTokens = append(refreshTokens, refreshToken)
		}

		service, emailManagerMock := getTestServiceAndEmailManager()

		err := service.SendVerifCodeForPasswordUpdate(ctx, entity.id)
		assert.NoError(t, err)

		correctVerifCode := emailManagerMock.ReadInbox(ctx, t, entity.email)

		const indexOfVictimRefreshToken = 0

		const accountNewPassword = "new_password123"
		updatePasswordDTO := &UpdatePasswordDTO{
			RefreshToken:      refreshTokens[indexOfVictimRefreshToken],
			NewPassword:       accountNewPassword,
			FeelLikeGetHacked: false,
			ProvidedVerifCode: correctVerifCode,
		}

		newRefreshToken, err := service.UpdatePassword(ctx, updatePasswordDTO, keyReader)
		assert.NoError(t, err)

		for index, rt := range refreshTokens {
			if index == indexOfVictimRefreshToken {
				_, err = service.GetAccessToken(ctx, rt, keyReader)
				common.AssertClientSideError(t, err)

				continue
			}

			_, err = service.GetAccessToken(ctx, rt, keyReader)
			assert.NoError(t, err)
		}

		_, err = service.GetAccessToken(ctx, newRefreshToken, keyReader)
		assert.NoError(t, err)

		actualEncryptedPassword := readEncryptedPassword(ctx, t, entity.id)

		err = bcrypt.CompareHashAndPassword(actualEncryptedPassword, []byte(accountNewPassword))
		assert.NoError(t, err)

		actualNotification := emailManagerMock.ReadInbox(ctx, t, entity.email)

		assert.Equal(t, testPasswordUpdateNotification, actualNotification)

		assertInMemoryStorageIsCleaned(ctx, t)
	})

	t.Run("updating password when 'feel like get hacked' is true", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestDB(ctx, t)
		common.ClearTestRedis(ctx)

		entity := getTestEntity(t)

		const accountCurrentPassword = "test_password123"
		createTestAccount(ctx, t, entity, accountCurrentPassword)

		var refreshTokens []string
		keyReader := auth.MockKeyReader{}

		for i := 0; i < 4; i++ {
			generatedUUID, err := uuid.NewRandom()
			assert.NoError(t, err)

			session := &Session{
				id:        generatedUUID.String(),
				accountID: entity.id,
			}

			createSession(ctx, t, session)

			refreshToken, err := auth.GenerateRefreshToken(entity.id, session.id, keyReader)
			assert.NoError(t, err)

			refreshTokens = append(refreshTokens, refreshToken)
		}

		service, emailManagerMock := getTestServiceAndEmailManager()

		err := service.SendVerifCodeForPasswordUpdate(ctx, entity.id)
		assert.NoError(t, err)

		correctVerifCode := ""

		for correctVerifCode == "" {
			correctVerifCode = emailManagerMock.readInbox(entity.email)
		}

		const accountNewPassword = "new_password123"

		updatePasswordDTO := &UpdatePasswordDTO{
			RefreshToken:      refreshTokens[0],
			NewPassword:       accountNewPassword,
			FeelLikeGetHacked: true,
			ProvidedVerifCode: correctVerifCode,
		}

		newRefreshToken, err := service.UpdatePassword(ctx, updatePasswordDTO, keyReader)
		assert.NoError(t, err)

		for _, rt := range refreshTokens {
			_, err = service.GetAccessToken(ctx, rt, keyReader)
			common.AssertClientSideError(t, err)
		}

		_, err = service.GetAccessToken(ctx, newRefreshToken, keyReader)
		assert.NoError(t, err)

		actualEncryptedPassword := readEncryptedPassword(ctx, t, entity.id)

		err = bcrypt.CompareHashAndPassword(actualEncryptedPassword, []byte(accountNewPassword))
		assert.NoError(t, err)

		actualNotification := emailManagerMock.ReadInbox(ctx, t, entity.email)

		assert.Equal(t, testPasswordUpdateNotification, actualNotification)

		assertInMemoryStorageIsCleaned(ctx, t)
	})
}

func TestService_PasswordResetFlow(t *testing.T) {
	t.Run("test happy path for password reset", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		entity := getTestEntity(t)
		createTestAccount(ctx, t, entity, "existing_password123123")

		service, emailManagerMock := getTestServiceAndEmailManager()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		correctCaptchaAnswer := readCaptchaAnswer(ctx, t, captchaID)

		passwordResetRequestDto := &PasswordResetRequestDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 entity.email,
		}

		pipeID, err := service.CreatePasswordResetRequest(ctx, passwordResetRequestDto)
		assert.NotEmpty(t, pipeID)
		assert.NoError(t, err)

		verifCode := emailManagerMock.ReadInbox(ctx, t, entity.email)

		const newPassword = "new_password123123"

		peformPasswordResetDto := &PerformPasswordResetDTO{
			VerifCode:   verifCode,
			PipeID:      pipeID,
			Email:       entity.email,
			NewPassword: newPassword,
		}

		err = service.PerformPasswordReset(ctx, peformPasswordResetDto)
		assert.NoError(t, err)

		actualEncryptedPassword := readEncryptedPassword(ctx, t, entity.id)

		err = bcrypt.CompareHashAndPassword(actualEncryptedPassword, []byte(newPassword))
		assert.NoError(t, err)

		passwordResetNotification := emailManagerMock.ReadInbox(ctx, t, entity.email)

		assert.Equal(t, testPasswordResetNotification, passwordResetNotification)

		assertInMemoryStorageIsCleaned(ctx, t)
	})

	t.Run("invalid input parameters for finishing password reset procedure", func(t *testing.T) {
		ctx := context.TODO()

		common.ClearTestRedis(ctx)
		common.ClearTestDB(ctx, t)

		entity := getTestEntity(t)
		createTestAccount(ctx, t, entity, "existing_password123123")

		service, emailManagerMock := getTestServiceAndEmailManager()

		const captchaTypeImage = 1

		captchaID, _, err := service.GenerateCaptcha(ctx, captchaTypeImage)
		assert.NoError(t, err)

		correctCaptchaAnswer := readCaptchaAnswer(ctx, t, captchaID)

		passwordResetRequestDto := &PasswordResetRequestDTO{
			CaptchaID:             captchaID,
			ProvidedCaptchaAnswer: correctCaptchaAnswer,
			Email:                 entity.email,
		}

		correctPipeID, err := service.CreatePasswordResetRequest(ctx, passwordResetRequestDto)
		assert.NotEmpty(t, correctPipeID)
		assert.NoError(t, err)

		correctVerifCode := emailManagerMock.ReadInbox(ctx, t, entity.email)

		incorrectPipeID, err := uuid.NewRandom()
		assert.NoError(t, err)

		incorrectPipeIDAsStr := incorrectPipeID.String()

		testCases := []struct {
			name      string
			verifCode string
			pipeID    string
		}{
			{
				name:      "invalid verif code",
				verifCode: common.ReverseString(correctVerifCode),
				pipeID:    correctPipeID,
			},
			{
				name:      "invalid pipe id",
				verifCode: correctVerifCode,
				pipeID:    incorrectPipeIDAsStr,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				const newPassword = "new_password123123"

				peformPasswordResetDto := &PerformPasswordResetDTO{
					VerifCode:   tc.verifCode,
					PipeID:      tc.pipeID,
					Email:       entity.email,
					NewPassword: newPassword,
				}

				err = service.PerformPasswordReset(ctx, peformPasswordResetDto)
				common.AssertClientSideError(t, err)
			})
		}
	})
}
