package account

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

func TestRepository_ReadByID(t *testing.T) {
	testCases := []struct {
		name                      string
		shouldCreateAccountBefore bool
		shouldGetClientSideErr    bool
	}{
		{
			name:                      "should successfully read account by ID",
			shouldCreateAccountBefore: true,
			shouldGetClientSideErr:    false,
		},
		{
			name:                      "should not get user by id",
			shouldCreateAccountBefore: false,
			shouldGetClientSideErr:    true,
		},
	}

	repository := getTestAccountRepository()
	ctx := context.TODO()

	for _, tc := range testCases {
		common.ClearTestDB(ctx, t)

		t.Run(tc.name, func(t *testing.T) {
			initialEntity := getTestEntity(t)

			if tc.shouldCreateAccountBefore {
				createTestAccount(ctx, t, initialEntity, "test_password123")
			}

			actualEntity, err := repository.ReadByID(ctx, initialEntity.id)

			if tc.shouldGetClientSideErr {
				assert.Nil(t, actualEntity)
				common.AssertClientSideError(t, err)

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, actualEntity)
		})
	}
}

func TestRepository_ReadByIDWithEncryptedPass(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)
	createTestAccount(ctx, t, entity, "test123")

	repository := getTestAccountRepository()

	const incorrectUserID = "e028297a-ba67-49e5-89e2-f0546e64bfa8"
	actualEntity, encryptedPass, err := repository.ReadByIDWithEncryptedPass(ctx, incorrectUserID)

	assert.Nil(t, actualEntity)
	assert.Nil(t, encryptedPass)
	common.AssertClientSideError(t, err)

	actualEntity1, encryptedPass1, err := repository.ReadByIDWithEncryptedPass(ctx, entity.id)

	assert.NotNil(t, actualEntity1)
	assert.NotEmpty(t, encryptedPass1)
	assert.NoError(t, err)
}

func TestRepository_Create(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	initialEntity := getTestEntity(t)
	repository := getTestAccountRepository()

	password := "test_password123"

	encryptedPassword, err := encryptUserPassword(password)
	assert.NoError(t, err)

	err = repository.CreateNew(ctx, initialEntity, encryptedPassword)
	assert.NoError(t, err)

	actualEntity := readTestAccount(ctx, t, initialEntity.id)
	assert.Equal(t, initialEntity, actualEntity)
}

func TestRepository_Update(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	initialEntity := getTestEntity(t)

	repository := getTestAccountRepository()

	createTestAccount(ctx, t, initialEntity, "test_password123")

	initialEntity.firstName = "updated"
	initialEntity.lastName = "updated"

	err := repository.Update(ctx, initialEntity)
	assert.NoError(t, err)

	actualEntity := readTestAccount(ctx, t, initialEntity.id)

	assert.Equal(t, initialEntity, actualEntity)
}

func TestRepository_CheckIfCanBeSaved(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)

	createTestAccount(ctx, t, entity, "test_password123")

	testCases := []struct {
		name string

		email    string
		nickname string

		expectedResult int
	}{
		{
			name: "should return false because user with such email already exists",

			email:    entity.email,
			nickname: "different nickname",

			expectedResult: 1,
		},
		{
			name: "should return false because user with such nickname already exists",

			email:    "different email",
			nickname: entity.nickname,

			expectedResult: 1,
		},
		{
			name: "should return false because user with such email and nickname already exists",

			email:    entity.email,
			nickname: entity.nickname,

			expectedResult: 1,
		},
		{
			name: "should return true because there's no user with such email or nickname",

			email:    "different email",
			nickname: "different nickname",

			expectedResult: 0,
		},
	}

	repository := getTestAccountRepository()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualResult, err := repository.CountUsersWithEmailOrNickname(ctx, tc.email, tc.nickname)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, actualResult)
		})
	}
}

func TestRepository_ReadByNickname(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	repository := getTestAccountRepository()
	entity := getTestEntity(t)

	actualEntity, err := repository.ReadByNickname(context.Background(), entity.nickname)

	assert.Nil(t, actualEntity)
	common.AssertClientSideError(t, err)

	createTestAccount(ctx, t, entity, "test123")

	actualEntity1, err := repository.ReadByNickname(context.Background(), entity.nickname)

	assert.NotNil(t, actualEntity1)
	assert.NoError(t, err)
}

func TestRepository_ReadByEmailWithEncryptedPass(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)
	createTestAccount(ctx, t, entity, "test123")

	repository := getTestAccountRepository()

	actualEntity, encryptedPass, err := repository.ReadByEmailWithEncryptedPass(context.Background(), entity.email)

	assert.NotNil(t, actualEntity)
	assert.NotEmpty(t, encryptedPass)
	assert.NoError(t, err)
}

func TestRepository_IsAvailableEmail(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)

	createTestAccount(ctx, t, entity, "test123")
	repository := getTestAccountRepository()

	testCases := []struct {
		name string

		mail           string
		expectedResult int
	}{
		{
			name: "existing email",

			mail:           entity.email,
			expectedResult: 1,
		},
		{
			name: "non-existing email",

			mail:           "notExists@mail.com",
			expectedResult: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualResult, err := repository.CountUsersWithEmail(ctx, tc.mail)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, actualResult)
		})
	}
}

func TestRepository_IsAvailableNickname(t *testing.T) {
	ctx := context.TODO()
	common.ClearTestDB(ctx, t)

	entity := getTestEntity(t)

	createTestAccount(ctx, t, entity, "test123")
	repository := getTestAccountRepository()

	testCases := []struct {
		name string

		nickname       string
		expectedResult int
	}{
		{
			name:           "existing nickname",
			nickname:       entity.nickname,
			expectedResult: 1,
		},
		{
			name:           "non-existing nickname",
			nickname:       "notExists",
			expectedResult: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			available, err := repository.CountUsersWithNickname(ctx, tc.nickname)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, available)
		})
	}
}
