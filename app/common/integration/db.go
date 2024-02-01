package integration

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/GonnaFlyMethod/gofundament/app/common/config"
)

const (
	NameOfAccountsCollection = "accounts"
	NameOfSessionsCollection = "sessions"
)

func NewMongoConnection(ctx context.Context, dbConfig config.DatabaseConfig) (*mongo.Client, error) {
	connectionString := dbConfig.ConnectionString()

	mongoClientOptions := options.Client().
		SetConnectTimeout(20 * time.Second).
		ApplyURI(connectionString)

	mongoClient, err := mongo.Connect(ctx, mongoClientOptions)
	if err != nil {
		return nil, err
	}

	if err = mongoClient.Ping(ctx, nil); err != nil {
		return nil, errors.Wrap(err, "error occurred while pinging Mongo DB")
	}

	return mongoClient, nil
}
