package account

import (
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DBModel struct {
	ID                primitive.Binary    `bson:"_id"`
	FirstName         string              `bson:"first_name"`
	LastName          string              `bson:"last_name"`
	Nickname          string              `bson:"nickname"`
	Email             string              `bson:"email"`
	BirthDate         time.Time           `bson:"birth_date"`
	CurrentCountry    string              `bson:"current_country"`
	CreatedAt         primitive.Timestamp `bson:"created_at"`
	UpdatedAt         primitive.Timestamp `bson:"updated_at"`
	EncryptedPassword primitive.Binary    `bson:"encrypted_password"`
}

func convertAccountToDBModel(account *Entity) (*DBModel, error) {
	preparedUUID, err := prepareIDForStorage(account.id)
	if err != nil {
		return nil, err
	}

	readyForConversionCreatedAt := uint32(account.createdAt.Unix())
	readyForConversionUpdatedAt := uint32(account.updatedAt.Unix())

	return &DBModel{
		ID:             primitive.Binary{Data: preparedUUID, Subtype: bsontype.BinaryUUID},
		FirstName:      account.firstName,
		LastName:       account.lastName,
		Nickname:       account.nickname,
		Email:          account.email,
		BirthDate:      account.birthDate,
		CurrentCountry: account.currentCountry,
		CreatedAt:      primitive.Timestamp{T: readyForConversionCreatedAt},
		UpdatedAt:      primitive.Timestamp{T: readyForConversionUpdatedAt},
	}, nil
}

func convertDBModelToAccount(dbModel *DBModel) (*Entity, error) {
	initialUUID, err := uuid.FromBytes(dbModel.ID.Data)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while creating uuid from bytes (account)")
	}

	return &Entity{
		id:             initialUUID.String(),
		firstName:      dbModel.FirstName,
		lastName:       dbModel.LastName,
		nickname:       dbModel.Nickname,
		email:          dbModel.Email,
		birthDate:      dbModel.BirthDate,
		currentCountry: dbModel.CurrentCountry,
		createdAt:      time.Unix(int64(dbModel.CreatedAt.T), 0),
		updatedAt:      time.Unix(int64(dbModel.UpdatedAt.T), 0),
	}, nil
}

type SessionDBModel struct {
	ID        primitive.Binary `bson:"_id"`
	AccountID primitive.Binary `bson:"account_id"`
}

func convertSessionToDBModel(session *Session) (*SessionDBModel, error) {
	preparedID, err := prepareIDForStorage(session.id)
	if err != nil {
		return nil, err
	}

	preparedAccountID, err := prepareIDForStorage(session.accountID)
	if err != nil {
		return nil, err
	}

	return &SessionDBModel{
		ID:        primitive.Binary{Data: preparedID, Subtype: bsontype.BinaryUUID},
		AccountID: primitive.Binary{Data: preparedAccountID, Subtype: bsontype.BinaryUUID},
	}, nil
}
