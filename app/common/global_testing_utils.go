package common

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/GonnaFlyMethod/gofundament/app/common/config"
	"github.com/GonnaFlyMethod/gofundament/app/common/integration"
)

var (
	dbConnectionOnce sync.Once
	testDB           *mongo.Client
)

const (
	testDBName = "test"
)

func GetTestDBClient() *mongo.Client {
	dbConnectionOnce.Do(func() {
		ctx := context.TODO()

		globalConfig := config.BuildFromEnv()
		connectionString := globalConfig.Database.ConnectionString()

		connectionOptions := options.Client().ApplyURI(connectionString)

		connection, err := mongo.Connect(ctx, connectionOptions)
		if err != nil {
			panicMsg := fmt.Sprintf("error occurred while connection to DB, err: %v", err)
			panic(panicMsg)
		}

		if err = connection.Ping(ctx, nil); err != nil {
			panicMsg := fmt.Sprintf("error occurred while pinging DB, err: %v", err)
			panic(panicMsg)
		}

		testDB = connection
	})

	return testDB
}

var (
	accountsCollection        *mongo.Collection
	getAccountsCollectionOnce sync.Once
)

func GetTestAccountsCollection() *mongo.Collection {
	getAccountsCollectionOnce.Do(func() {
		dbClient := GetTestDBClient()
		accountsCollection = dbClient.Database(testDBName).Collection(integration.NameOfAccountsCollection)
	})

	return accountsCollection
}

var (
	sessionsCollection        *mongo.Collection
	getSessionsCollectionOnce sync.Once
)

func GetTestSessionsCollection() *mongo.Collection {
	getSessionsCollectionOnce.Do(func() {
		dbClient := GetTestDBClient()
		sessionsCollection = dbClient.Database(testDBName).Collection(integration.NameOfSessionsCollection)
	})

	return sessionsCollection
}

func ClearTestDB(ctx context.Context, t *testing.T) {
	t.Helper()

	testDBClient := GetTestDBClient()
	database := testDBClient.Database(testDBName)

	collectionsToTruncate, err := database.ListCollectionNames(ctx, bson.D{{}})
	assert.NoError(t, err)

	for _, collectionName := range collectionsToTruncate {
		_, err := database.Collection(collectionName).DeleteMany(ctx, bson.D{{}})
		assert.NoError(t, err)
	}
}

var (
	redisClient     *redis.Client
	redisClientOnce sync.Once
)

func GetTestRedisClient() *redis.Client {
	redisClientOnce.Do(func() {
		globalConfig := config.BuildFromEnv()

		addr := fmt.Sprintf("%s:%s", globalConfig.InMemoryStorage.Host, globalConfig.InMemoryStorage.Port)

		redisClientOptions := &redis.Options{
			Addr:         addr,
			Password:     globalConfig.InMemoryStorage.Password,
			DB:           0,
			DialTimeout:  3 * time.Second,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		}

		redisClient = redis.NewClient(redisClientOptions)

		ctx := context.TODO()

		if _, err := redisClient.Ping(ctx).Result(); err != nil {
			panicMsg := fmt.Sprintf("error has occurred while pinging redis, err: %v", err)
			panic(panicMsg)
		}
	})

	return redisClient
}

func ClearTestRedis(ctx context.Context) {
	getTestRedisClient := GetTestRedisClient()
	getTestRedisClient.FlushDB(ctx)
}

func AssertClientSideError(t *testing.T, err error) {
	t.Helper()

	cse := new(ClientSideError)

	assert.ErrorAs(t, err, &cse)
}

func AssertValidationError(t *testing.T, err error) {
	t.Helper()

	ve := new(ValidationError)

	assert.ErrorAs(t, err, &ve)
}

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
