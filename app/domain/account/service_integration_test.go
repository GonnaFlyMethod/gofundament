package account

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest/auth"
)

func TestService_GenerateCaptcha(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestRedis(ctx)

	service := getTestService()

	const (
		captchaTypeImage = 1
		captchaTypeAudio = 2
	)

	captchaID, b64s, err := service.GenerateCaptcha(ctx, captchaTypeImage)
	assert.NoError(t, err)

	assert.NotEmpty(t, captchaID)
	assert.NotEmpty(t, b64s)

	captchaID1, b64s1, err := service.GenerateCaptcha(ctx, captchaTypeAudio)
	assert.NoError(t, err)

	assert.NotEmpty(t, captchaID1)
	assert.NotEmpty(t, b64s1)
}

func TestService_StartSignUpPipe(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestRedis(ctx)
	common.ClearTestDB(ctx, t)

	service := getTestService()

	dto := &StartSignUpPipeDTO{
		CaptchaID:             "DDTJ2B7usaJzbrAnzZBT",
		ProvidedCaptchaAnswer: "64273",
		Email:                 "test.email@domain.com",
		Nickname:              "test_nickname",
	}

	pipeID, err := service.StartSignUpPipe(ctx, dto)
	assert.Empty(t, pipeID)
	common.AssertClientSideError(t, err)
}

func TestService_ResendVerifCodeForSignUp(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestRedis(ctx)

	service := getTestService()

	generatedUUID, err := uuid.NewRandom()
	assert.NoError(t, err)

	generatedUUIDAsStr := generatedUUID.String()

	err = service.ResendVerifCodeForSignUp(ctx, generatedUUIDAsStr)
	common.AssertClientSideError(t, err)
}

func TestService_SignUp(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestRedis(ctx)
	common.ClearTestDB(ctx, t)

	service := getTestService()

	generatedUUID, err := uuid.NewRandom()
	assert.NoError(t, err)

	dto := &SignUpDTO{
		ProvidedVerifCode: "512345",
		PipeID:            generatedUUID.String(),
	}

	err = service.SignUp(ctx, dto)
	common.AssertClientSideError(t, err)
}

func TestService_SendVerifCodeForPasswordUpdate(t *testing.T) {
	t.Run("testing behavior when user with provided id exists/does not exist", func(t *testing.T) {
		testCases := []struct {
			name string

			shouldCreateAccountBefore bool
			shouldGetErr              bool
		}{
			{
				name:                      "should successfully send verif code",
				shouldCreateAccountBefore: true,
				shouldGetErr:              false,
			},
			{
				name:                      "should get error because account with provided accountID does not exist",
				shouldCreateAccountBefore: false,
				shouldGetErr:              true,
			},
		}

		service := getTestService()

		ctx := context.TODO()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				common.ClearTestRedis(ctx)
				common.ClearTestDB(ctx, t)

				entity := getTestEntity(t)

				if tc.shouldCreateAccountBefore {
					createTestAccount(ctx, t, entity, "test_password123")
				}

				err := service.SendVerifCodeForPasswordUpdate(ctx, entity.id)

				if tc.shouldGetErr {
					common.AssertClientSideError(t, err)
					return
				}

				assert.NoError(t, err)
			})
		}
	})
}

func TestService_CreatePasswordResetRequest(t *testing.T) {
	ctx := context.TODO()

	common.ClearTestRedis(ctx)
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)
	createTestAccount(ctx, t, entity, "test_password123")

}

func TestService_GetAccessToken(t *testing.T) {
	t.Run("testing behaviour that depends on validity of refresh token", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestDB(ctx, t)

		entity := getTestEntity(t)
		createTestAccount(ctx, t, entity, "test_password123")

		generatedUUID, err := uuid.NewRandom()
		assert.NoError(t, err)

		session := &Session{
			id:        generatedUUID.String(),
			accountID: entity.id,
		}

		mockKeyReader := auth.MockKeyReader{}

		validRefreshToken, err := auth.GenerateRefreshToken(entity.id, session.id, mockKeyReader)
		assert.NoError(t, err)

		createSession(ctx, t, session)

		testCases := []struct {
			name         string
			refreshToken string
			shouldGetErr bool
		}{
			{
				name:         "should successfully get access token",
				refreshToken: validRefreshToken,
				shouldGetErr: false,
			},
			{
				name:         "should get error because of invalid refresh token",
				refreshToken: common.ReverseString(validRefreshToken),
				shouldGetErr: true,
			},
		}

		service := getTestService()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				accessToken, err := service.GetAccessToken(ctx, tc.refreshToken, mockKeyReader)

				if tc.shouldGetErr {
					assert.Empty(t, accessToken)
					common.AssertClientSideError(t, err)

					return
				}

				assert.NotEmpty(t, accessToken)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("testing behaviour that depends on session's existence in storage", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestDB(ctx, t)

		service := getTestService()

		entity := getTestEntity(t)
		createTestAccount(ctx, t, entity, "test_password123")

		generatedUUID, err := uuid.NewRandom()
		assert.NoError(t, err)

		session := &Session{
			id:        generatedUUID.String(),
			accountID: entity.id,
		}

		mockKeyReader := auth.MockKeyReader{}
		refreshToken, err := auth.GenerateRefreshToken(entity.id, session.id, mockKeyReader)
		assert.NoError(t, err)

		accessToken, err := service.GetAccessToken(ctx, refreshToken, mockKeyReader)
		common.AssertClientSideError(t, err)
		assert.Empty(t, accessToken)

		createSession(ctx, t, session)

		accessToken, err = service.GetAccessToken(ctx, refreshToken, mockKeyReader)
		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})
}

func TestService_Logout(t *testing.T) {
	t.Run("invalid refresh token", func(t *testing.T) {
		ctx := context.TODO()
		service := getTestService()

		//nolint:gosec
		invalidRefreshToken := "testbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwb3J0Zm9saW8uYXV0aCJ9.c5rpL2G_PQX9jvjF4OVWX-tfDRy9Rrfsar6e4gxyGnlEbJjKx7_j4N1S0gSmV4OjbNuWl5HPTcWhE-xBatguhBBSJ4fd3awc9EY_KxEhfICp-Gy7RmeP5TcZuLUdMpzoaZKkQ9_wAUNq4oOt82TVtn3l6sunBJf16DTW-o9B7VsH9GYjcHgI8lG3A3QTD5RRAxYZF8S8wq8Gb1sLuiXSJE_AFGZge1IPgwMPrLw9wDS3I3UzPcGm24XkbAv3euL3QIggQPv1TAJloZi_dNAOkDFkPzFQxh1QktqSqe0v9Gxf4pTFOEp-Su6aebI46cOtGyaAIfzd4puKTb1UwpN89g"
		mockKeyReader := auth.MockKeyReader{}

		err := service.Logout(ctx, invalidRefreshToken, mockKeyReader)
		common.AssertClientSideError(t, err)
	})

	t.Run("logout success", func(t *testing.T) {
		ctx := context.TODO()
		common.ClearTestDB(ctx, t)

		service := getTestService()

		entity := getTestEntity(t)
		createTestAccount(ctx, t, entity, "test_password123")

		generatedUUID, err := uuid.NewRandom()
		assert.NoError(t, err)

		session := &Session{
			id:        generatedUUID.String(),
			accountID: entity.id,
		}

		mockKeyReader := auth.MockKeyReader{}

		refreshToken, err := auth.GenerateRefreshToken(entity.id, session.id, mockKeyReader)
		assert.NoError(t, err)

		createSession(ctx, t, session)

		actualNumOfSessionsBeforeLogOut := countSessions(ctx, t, entity.id)
		assert.Equal(t, 1, actualNumOfSessionsBeforeLogOut)

		err = service.Logout(ctx, refreshToken, mockKeyReader)
		assert.NoError(t, err)

		actualNumOfSessionsAfterLogOut := countSessions(ctx, t, entity.id)
		assert.Equal(t, 0, actualNumOfSessionsAfterLogOut)
	})
}

func TestService_GetAccount(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	const password = "test_password"

	user := getTestEntity(t)

	service := getTestService()

	actual, err := service.GetAccount(ctx, user.nickname)
	common.AssertClientSideError(t, err)
	assert.Nil(t, actual)

	createTestAccount(ctx, t, user, password)

	actual, err = service.GetAccount(ctx, user.nickname)
	assert.NoError(t, err)
	assert.Equal(t, user, actual)
}

func TestService_IsExistingEmail(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)
	createTestAccount(ctx, t, entity, "test")

	testCases := []struct {
		name   string
		email  string
		expect bool
	}{
		{
			name:   "Existing email",
			email:  entity.email,
			expect: false,
		},
		{
			name:   "Non-existing email",
			email:  "qwerty",
			expect: true,
		},
	}

	service := getTestService()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := service.IsAvailableEmail(ctx, tc.email)

			assert.NoError(t, err)
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestService_IsAvailableNickname(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)
	createTestAccount(ctx, t, entity, "test")

	testCases := []struct {
		name     string
		nickname string
		expect   bool
	}{
		{
			name:     "Existing nickname",
			nickname: entity.nickname,
			expect:   false,
		},
		{
			name:     "Non-existing nickname",
			nickname: "qwerty",
			expect:   true,
		},
	}

	service := getTestService()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := service.IsAvailableNickname(ctx, tc.nickname)

			assert.NoError(t, err)
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestService_UpdateAccount(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	sut := getTestService()
	now := time.Now()

	const entityID = "0184edeb-a9ff-55f1-0e6b-4a771d418e5e"

	actualAccount := &Entity{
		id:             entityID,
		birthDate:      getTestBirthDate(),
		nickname:       "test",
		email:          "test@mail.com",
		currentCountry: "US",
		createdAt:      now,
		updatedAt:      now,
	}
	createTestAccount(ctx, t, actualAccount, "test")

	accountToUpdate := &UpdateAccountDTO{
		ID:             entityID,
		BirthDate:      getTestBirthDate(),
		CurrentCountry: "AU",
		FirstName:      "John",
		LastName:       "Smith",
	}

	err := sut.UpdateAccount(ctx, accountToUpdate)
	assert.NoError(t, err)

	actualAccount = readTestAccount(ctx, t, actualAccount.id)

	assert.Equal(t, accountToUpdate.BirthDate, actualAccount.birthDate)

	assert.Equal(t, accountToUpdate.CurrentCountry, actualAccount.currentCountry)
	assert.Equal(t, accountToUpdate.FirstName, actualAccount.firstName)
	assert.Equal(t, accountToUpdate.LastName, actualAccount.lastName)
}
