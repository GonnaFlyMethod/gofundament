package depcontainer

import (
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/GonnaFlyMethod/gofundament/app/common/config"
	"github.com/GonnaFlyMethod/gofundament/app/common/integration"
	"github.com/GonnaFlyMethod/gofundament/app/domain/account"
)

type DependenciesContainer struct {
	AccountService *account.Service
}

func NewDependenciesContainer(globalConfig config.Config, mongoClient *mongo.Client, redisClient *redis.Client) *DependenciesContainer {
	emailManager := integration.NewEmailManager(globalConfig)

	dbName := globalConfig.Database.DatabaseName

	accountsCollection := mongoClient.Database(dbName).Collection(integration.NameOfAccountsCollection)
	sessionsCollection := mongoClient.Database(dbName).Collection(integration.NameOfSessionsCollection)

	accountRepository := account.NewAccountRepository(accountsCollection)
	sessionRepository := account.NewSessionRepository(mongoClient, sessionsCollection)
	accountSessionTxn := account.NewAccountSessionTxn(mongoClient, accountRepository, sessionRepository)

	accountInMemoryStorage := account.NewGeneralInMemoryStorage(redisClient)

	accountService := account.NewService(
		emailManager, accountRepository, sessionRepository, accountSessionTxn, accountInMemoryStorage)

	return &DependenciesContainer{
		AccountService: accountService,
	}
}
