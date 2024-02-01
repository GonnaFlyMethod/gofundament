package account

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

type mockEmailManager struct {
	mu    *sync.Mutex
	inbox map[string]string
}

func (em *mockEmailManager) readInbox(emailOfReceiver string) string {
	em.mu.Lock()
	result := em.inbox[emailOfReceiver]
	em.mu.Unlock()
	return result
}

func (em *mockEmailManager) ReadInbox(ctx context.Context, t *testing.T, email string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()

	gotValueFromInbox := make(chan bool)

	val := ""

	go func() {
		for val == "" {
			val = em.readInbox(email)
		}

		gotValueFromInbox <- true
	}()

	select {
	case <-ctx.Done():
		t.Fatal("context timeout while reading value from inbox")
	case <-gotValueFromInbox:
		return val
	}

	return val
}

func (em *mockEmailManager) setInbox(emailOfReceiver, message string) {
	em.mu.Lock()
	em.inbox[emailOfReceiver] = message
	em.mu.Unlock()
}

func (em *mockEmailManager) SendVerifCodeForSignUp(emailOfReceiver, _, code string) {
	em.setInbox(emailOfReceiver, code)
}

func (em *mockEmailManager) SendVerifCodeForPasswordUpdate(emailOfReceiver, code string) {
	em.setInbox(emailOfReceiver, code)
}

func (em *mockEmailManager) SendVerifCodeForPasswordReset(emailOfReceiver, code string) {
	em.setInbox(emailOfReceiver, code)
}

func (em *mockEmailManager) SendVerifCodeToCleanSessions(emailOfReceiver, code string) {
	em.setInbox(emailOfReceiver, code)
}

const (
	testPasswordUpdateNotification = "password update notification"
	testPasswordResetNotification  = "password reset notification"
)

func (em *mockEmailManager) SendPasswordUpdateNotification(emailOfReceiver string, _ bool) {
	em.setInbox(emailOfReceiver, testPasswordUpdateNotification)
}

func (em *mockEmailManager) SendPasswordResetNotification(emailOfReceiver string) {
	em.setInbox(emailOfReceiver, testPasswordResetNotification)
}

func getTestEntity(t *testing.T) *Entity {
	t.Helper()

	id, err := uuid.NewRandom()
	assert.NoError(t, err)

	timestamp := time.Now().Unix()
	timestampInUnix := time.Unix(timestamp, 0)

	return &Entity{
		id:             id.String(),
		firstName:      "John",
		lastName:       "Smith",
		nickname:       "JohnS",
		email:          "test@mail.com",
		birthDate:      getTestBirthDate(),
		currentCountry: "US",
		createdAt:      timestampInUnix,
		updatedAt:      timestampInUnix,
	}
}

func getTestBirthDate() time.Time {
	return time.Date(1997, 2, 13, 0, 0, 0, 0, time.UTC)
}

func getTestAccountRepository() *accountRepository {
	return &accountRepository{
		accountsCollection: common.GetTestAccountsCollection(),
	}
}

func getTestServiceAndEmailManager() (*Service, *mockEmailManager) {
	redisClient := common.GetTestRedisClient()
	accountsCollection := common.GetTestSessionsCollection()

	mongoClient := common.GetTestDBClient()

	accountsRep := getTestAccountRepository()
	sessionsRep := &sessionRepository{sessionsCollection: accountsCollection, client: mongoClient}

	emailManagerMock := &mockEmailManager{
		mu:    &sync.Mutex{},
		inbox: map[string]string{},
	}

	service := &Service{
		inMemoryStorage:   NewGeneralInMemoryStorage(redisClient),
		accountRepository: accountsRep,
		sessionRepository: sessionsRep,
		accountSessionTxn: &accountSessionTxn{
			client:            mongoClient,
			accountRepository: accountsRep,
			sessionRepository: sessionsRep,
		},
		emailManager: emailManagerMock,
	}

	return service, emailManagerMock
}

func getTestService() *Service {
	service, _ := getTestServiceAndEmailManager()
	return service
}

func createTestAccount(ctx context.Context, t *testing.T, account *Entity, plainPassword string) {
	t.Helper()

	dbModel, err := convertAccountToDBModel(account)
	assert.NoError(t, err)

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.MinCost)
	assert.NoError(t, err)

	dbModel.EncryptedPassword = primitive.Binary{Data: encryptedPassword}

	collection := common.GetTestAccountsCollection()

	_, err = collection.InsertOne(ctx, dbModel)
	assert.NoError(t, err)
}

func readTestAccount(ctx context.Context, t *testing.T, id string) *Entity {
	t.Helper()

	collection := common.GetTestAccountsCollection()

	preparedID, err := prepareIDForStorage(id)
	assert.NoError(t, err)

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedID,
	}}

	var dbModel DBModel
	result := collection.FindOne(ctx, filter)

	err = result.Decode(&dbModel)
	assert.NoError(t, err)

	entity, err := convertDBModelToAccount(&dbModel)
	assert.NoError(t, err)

	return entity
}

func readTestAccounts(ctx context.Context, t *testing.T) []*Entity {
	t.Helper()

	collection := common.GetTestAccountsCollection()

	cur, err := collection.Find(ctx, bson.D{{}})
	assert.NoError(t, err)

	var dbModels []*DBModel

	err = cur.All(ctx, &dbModels)
	assert.NoError(t, err)

	entities := make([]*Entity, 0)

	for _, dbModel := range dbModels {
		entity, err := convertDBModelToAccount(dbModel)
		assert.NoError(t, err)

		entities = append(entities, entity)
	}

	return entities
}

func readEncryptedPassword(ctx context.Context, t *testing.T, accountID string) []byte {
	t.Helper()

	collection := common.GetTestAccountsCollection()

	preparedAccountID, err := prepareIDForStorage(accountID)
	assert.NoError(t, err)

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedAccountID,
	}}

	result := collection.FindOne(ctx, filter)

	var dbModel DBModel

	err = result.Decode(&dbModel)
	assert.NoError(t, err)

	return dbModel.EncryptedPassword.Data
}

func readCaptchaAnswer(ctx context.Context, t *testing.T, captchaID string) string {
	t.Helper()

	redisKeyForCaptchaOfCurUsr := fmt.Sprintf(captchaKey, captchaID)
	redisClient := common.GetTestRedisClient()

	captchaAnswer, err := redisClient.Get(ctx, redisKeyForCaptchaOfCurUsr).Result()
	assert.NoError(t, err)

	return captchaAnswer
}

func createSession(ctx context.Context, t *testing.T, session *Session) {
	t.Helper()

	collection := common.GetTestSessionsCollection()

	dbModel, err := convertSessionToDBModel(session)
	assert.NoError(t, err)

	_, err = collection.InsertOne(ctx, dbModel)
	assert.NoError(t, err)
}

func countSessions(ctx context.Context, t *testing.T, accountID string) int {
	t.Helper()

	collection := common.GetTestSessionsCollection()

	preparedID, err := prepareIDForStorage(accountID)
	assert.NoError(t, err)

	filter := bson.M{"account_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedID,
	}}

	numOfSessions, err := collection.CountDocuments(ctx, filter)
	assert.NoError(t, err)

	return int(numOfSessions)
}

func isGlobalBanForSignIn(ctx context.Context, t *testing.T, ipOfClient string) bool {
	t.Helper()

	redisClient := common.GetTestRedisClient()

	redisKey := fmt.Sprintf(signInGlobalBanLimitKey, ipOfClient)

	result, err := redisClient.Exists(ctx, redisKey).Result()
	assert.NoError(t, err)

	return result == redisKeyExists
}

func isAccountBanForSignIn(ctx context.Context, t *testing.T, ipOfClient, accountID string) bool {
	t.Helper()

	redisClient := common.GetTestRedisClient()

	redisKey := formAccountBanLimitKey(ipOfClient, accountID)

	result, err := redisClient.Exists(ctx, redisKey).Result()
	assert.NoError(t, err)

	return result == redisKeyExists
}

func assertInMemoryStorageIsCleaned(ctx context.Context, t *testing.T) {
	t.Helper()

	redisClient := common.GetTestRedisClient()

	keys, err := redisClient.Keys(ctx, "*").Result()
	assert.NoError(t, err)

	assert.Len(t, keys, 0)
}
