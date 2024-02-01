package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"

	"github.com/GonnaFlyMethod/gofundament/app/common/config"
)

func NewRedisConnection(ctx context.Context, inMemoryStorageConfig config.InMemoryStorageConfig) (*redis.Client, error) {
	inMemoryStorageAddr := fmt.Sprintf("%s:%s", inMemoryStorageConfig.Host, inMemoryStorageConfig.Port)

	redisClientOptions := &redis.Options{
		Addr:         inMemoryStorageAddr,
		Password:     inMemoryStorageConfig.Password,
		DB:           0,
		DialTimeout:  8 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	redisConnection := redis.NewClient(redisClientOptions)

	if _, err := redisConnection.Ping(ctx).Result(); err != nil {
		return nil, errors.Wrap(err, "error occurred while pinging Redis")
	}

	return redisConnection, nil
}
