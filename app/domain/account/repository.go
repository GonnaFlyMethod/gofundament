package account

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

const (
	defaultWaitingTimeoutMongo = 5 * time.Second
)

type accountRepository struct {
	accountsCollection *mongo.Collection
}

func NewAccountRepository(accountsCollection *mongo.Collection) *accountRepository {
	return &accountRepository{
		accountsCollection: accountsCollection,
	}
}

func (r *accountRepository) CreateNew(ctx context.Context, account *Entity, encryptedPassword []byte) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	dbModel, err := convertAccountToDBModel(account)
	if err != nil {
		return err
	}

	dbModel.EncryptedPassword = primitive.Binary{Data: encryptedPassword}

	if _, err = r.accountsCollection.InsertOne(ctx, dbModel); err != nil {
		return errors.Wrap(err, "error occurred while inserting new account into storage")
	}

	return nil
}

func (r *accountRepository) Update(ctx context.Context, account *Entity) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	dbModel, err := convertAccountToDBModel(account)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    dbModel.ID.Data,
	}}

	updateDocument := bson.D{
		{
			Key: "$set",
			Value: bson.D{
				{Key: "first_name", Value: dbModel.FirstName},
				{Key: "last_name", Value: dbModel.LastName},
				{Key: "birth_date", Value: dbModel.BirthDate},
				{Key: "current_country", Value: dbModel.CurrentCountry},
				{Key: "updated_at", Value: dbModel.UpdatedAt},
			},
		},
	}
	if _, err = r.accountsCollection.UpdateOne(ctx, filter, updateDocument); err != nil {
		return err
	}

	return nil
}

func (r *accountRepository) UpdatePassword(ctx context.Context, account *Entity, encryptedPassword []byte) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	dbModel, err := convertAccountToDBModel(account)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    dbModel.ID.Data,
	}}

	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "encrypted_password", Value: encryptedPassword},
			{Key: "updated_at", Value: dbModel.UpdatedAt},
		}},
	}

	if _, err := r.accountsCollection.UpdateOne(ctx, filter, update); err != nil {
		return err
	}

	return nil
}

func (r *accountRepository) CountUsersWithEmailOrNickname(ctx context.Context, email, nickname string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	filter := bson.D{
		{Key: "$or", Value: []interface{}{
			bson.D{{Key: "email", Value: email}},
			bson.D{{Key: "nickname", Value: nickname}},
		}},
	}

	result, err := r.accountsCollection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}

	return int(result), nil
}

func (r *accountRepository) ReadByID(ctx context.Context, id string) (*Entity, error) {
	dbModel, err := r.readByID(ctx, id)
	if err != nil {
		return nil, err
	}

	entity, err := convertDBModelToAccount(dbModel)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

func (r *accountRepository) ReadByIDWithEncryptedPass(ctx context.Context, id string) (*Entity, []byte, error) {
	dbModel, err := r.readByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	entity, err := convertDBModelToAccount(dbModel)
	if err != nil {
		return nil, nil, err
	}

	return entity, dbModel.EncryptedPassword.Data, nil
}

func (r *accountRepository) readByID(ctx context.Context, id string) (*DBModel, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	preparedID, err := prepareIDForStorage(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedID,
	}}

	result := r.accountsCollection.FindOne(ctx, filter)

	var dbModel DBModel

	if err := result.Decode(&dbModel); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, common.NewClientSideError("account with provided id is not found")
		}

		return nil, errors.Wrap(err, "error from storage while reading account by id")
	}

	return &dbModel, nil
}

func (r *accountRepository) ReadByNickname(ctx context.Context, nickname string) (*Entity, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	var dbModel DBModel

	filter := bson.D{{Key: "nickname", Value: nickname}}

	result := r.accountsCollection.FindOne(ctx, filter)

	if err := result.Decode(&dbModel); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, common.NewClientSideError("account with provided nickname is not found")
		}

		return nil, errors.Wrap(err, "error from storage while reading account by nickname")
	}

	entity, err := convertDBModelToAccount(&dbModel)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

func (r *accountRepository) ReadByEmail(ctx context.Context, email string) (*Entity, error) {
	dbModel, err := r.readByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	entity, err := convertDBModelToAccount(dbModel)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

func (r *accountRepository) ReadByEmailWithEncryptedPass(ctx context.Context, email string) (*Entity, []byte, error) {
	dbModel, err := r.readByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}

	entity, err := convertDBModelToAccount(dbModel)
	if err != nil {
		return nil, nil, err
	}

	return entity, dbModel.EncryptedPassword.Data, nil
}

func (r *accountRepository) readByEmail(ctx context.Context, email string) (*DBModel, error) {
	// TODO: test timeouts
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	var dbModel DBModel

	filter := bson.D{{Key: "email", Value: email}}

	result := r.accountsCollection.FindOne(ctx, filter)

	if err := result.Decode(&dbModel); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, common.NewClientSideError("account with provided email is not found")
		}

		return nil, errors.Wrap(err, "error from storage while reading account by email")
	}

	return &dbModel, nil
}

func (r *accountRepository) CountUsersWithEmail(ctx context.Context, email string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}

	result, err := r.accountsCollection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}

	return int(result), nil
}

func (r *accountRepository) CountUsersWithNickname(ctx context.Context, nickname string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	filter := bson.D{{Key: "nickname", Value: nickname}}

	result, err := r.accountsCollection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}

	return int(result), nil
}

func prepareIDForStorage(id string) ([]byte, error) {
	parsedUUID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while parsing uuid")
	}

	marshaledUUID, err := parsedUUID.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while marshaling parsed uuid")
	}

	return marshaledUUID, nil
}

type sessionRepository struct {
	client             *mongo.Client
	sessionsCollection *mongo.Collection
}

func NewSessionRepository(client *mongo.Client, sessionsCollection *mongo.Collection) *sessionRepository {
	return &sessionRepository{client: client, sessionsCollection: sessionsCollection}
}

func (sr *sessionRepository) CreateNew(ctx context.Context, session *Session) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	dbModel, err := convertSessionToDBModel(session)
	if err != nil {
		return err
	}

	if _, err = sr.sessionsCollection.InsertOne(ctx, dbModel); err != nil {
		return errors.Wrap(err, "error occurred while inserting new session into storage")
	}

	return nil
}

func (sr *sessionRepository) CountNumOfSessionsBySessID(ctx context.Context, sessionID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	preparedSessionID, err := prepareIDForStorage(sessionID)
	if err != nil {
		return 0, err
	}

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedSessionID,
	}}

	result, err := sr.sessionsCollection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while counting number of sessions (by session id)")
	}

	return int(result), nil
}

func (sr *sessionRepository) CountNumOfSessionsByAccountID(ctx context.Context, accountID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	preparedAccountID, err := prepareIDForStorage(accountID)
	if err != nil {
		return 0, err
	}

	filter := bson.M{"account_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedAccountID,
	}}

	result, err := sr.sessionsCollection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while counting number of sessions (by account id)")
	}

	return int(result), nil
}

func (sr *sessionRepository) DeleteSessionsAndCreateNew(ctx context.Context, accountID string, session *Session) error {
	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if err := sr.DeleteSessions(sessCtx, accountID); err != nil {
			return nil, err
		}

		if err := sr.CreateNew(sessCtx, session); err != nil {
			return nil, err
		}

		//nolint:nilnil
		return nil, nil
	}

	mongoSession, err := sr.client.StartSession()
	if err != nil {
		return err
	}

	defer mongoSession.EndSession(ctx)

	_, err = mongoSession.WithTransaction(ctx, callback)
	if err != nil {
		return err
	}

	return nil
}

func (sr *sessionRepository) DeleteSessions(ctx context.Context, accountID string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	preparedAccountID, err := prepareIDForStorage(accountID)
	if err != nil {
		return err
	}

	filter := bson.M{"account_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedAccountID,
	}}

	if _, err := sr.sessionsCollection.DeleteMany(ctx, filter); err != nil {
		return errors.Wrap(err, "error occurred while deleting sessions from storage")
	}

	return nil
}

func (sr *sessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultWaitingTimeoutMongo)
	defer cancel()

	preparedSessionID, err := prepareIDForStorage(sessionID)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": primitive.Binary{
		Subtype: bsontype.BinaryUUID,
		Data:    preparedSessionID,
	}}

	if _, err := sr.sessionsCollection.DeleteOne(ctx, filter); err != nil {
		return errors.Wrap(err, "error occurred while deleting session from storage")
	}

	return nil
}

type accountSessionTxn struct {
	client            *mongo.Client
	accountRepository *accountRepository
	sessionRepository *sessionRepository
}

func NewAccountSessionTxn(client *mongo.Client, accountRepository *accountRepository, sessionRepository *sessionRepository) *accountSessionTxn {
	return &accountSessionTxn{client: client, accountRepository: accountRepository, sessionRepository: sessionRepository}
}

func (ast *accountSessionTxn) UpdatePassword(
	ctx context.Context,
	account *Entity,
	newEncryptedPassword []byte,
	newAccountSession *Session,
	sessionIDToDelete string,
) error {
	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Important: You must pass sessCtx as the Context parameter to the operations for them to be executed in the
		// transaction.
		if err := ast.accountRepository.UpdatePassword(sessCtx, account, newEncryptedPassword); err != nil {
			return nil, err
		}

		if err := ast.sessionRepository.DeleteSession(sessCtx, sessionIDToDelete); err != nil {
			return nil, err
		}

		if err := ast.sessionRepository.CreateNew(sessCtx, newAccountSession); err != nil {
			return nil, err
		}

		//nolint:nilnil
		return nil, nil
	}

	// Step 2: Start a session and run the callback using WithTransaction.
	mongoSession, err := ast.client.StartSession()
	if err != nil {
		return err
	}

	defer mongoSession.EndSession(ctx)

	_, err = mongoSession.WithTransaction(ctx, callback)
	if err != nil {
		return err
	}

	return nil
}

func (ast *accountSessionTxn) UpdatePasswordRadical(
	ctx context.Context,
	account *Entity,
	newEncryptedPassword []byte,
	newAccountSession *Session,
) error {
	accountID := account.GetID()

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		if err := ast.accountRepository.UpdatePassword(sessCtx, account, newEncryptedPassword); err != nil {
			return nil, err
		}

		if err := ast.sessionRepository.DeleteSessions(sessCtx, accountID); err != nil {
			return nil, err
		}

		if err := ast.sessionRepository.CreateNew(sessCtx, newAccountSession); err != nil {
			return nil, err
		}

		//nolint:nilnil
		return nil, nil
	}

	mongoSession, err := ast.client.StartSession()
	if err != nil {
		return err
	}

	defer mongoSession.EndSession(ctx)

	_, err = mongoSession.WithTransaction(ctx, callback)
	if err != nil {
		return err
	}

	return nil
}
