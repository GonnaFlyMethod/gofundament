package account

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

const (
	captchaKey = "captcha:%s"

	reservedNicknameKey = "registration_flow:reserved_nickname:%s"
	signingUpUserKey    = "registration_flow:signing_up_user:%s"

	signInGlobalBanTrackerKey  = "sign_in_tracker:global_ban:%s"
	signInCaptchaTrackerKey    = "sign_in_tracker:captcha:%s"
	signInAccountBanTrackerKey = "sing_in_tracker:account_ban:%s"

	signInGlobalBanLimitKey = "sign_in_limit:global_ban:%s"
	signInCaptchaLimitKey   = "sign_in_limit:captcha:%s"
	signAccountBanLimitKey  = "sign_in_limit:account_ban:%s"

	timeoutKey = "email_code_timeout:%s:%s"

	emailCodeTrackerKey = "email_code_tracker:%s:%s"
	emailCodeLimitKey   = "email_code_limit:ban:%s:%s"

	verifCodePoolKey          = "verif_code_pool:%s:%s"
	sessionsOverflowStatusKey = "sessions_overflow_status:%s"
)

const (
	expiration30Mins = 30 * time.Minute
	expiration1Hour  = 1 * time.Hour
	expiration1Day   = 24 * time.Hour
)

const redisKeyExists = 1

var operationsAndRedisRepresentations = map[int]string{
	operationSignUp:           "sign_up",
	operationPasswordUpdate:   "password_update",
	operationPasswordReset:    "password_reset",
	operationCleaningSessions: "cleaning_sessions",
}

func formTimeoutKey(operation int, identifier string) string {
	redisRepresentationOfOperation := operationsAndRedisRepresentations[operation]
	return fmt.Sprintf(timeoutKey, redisRepresentationOfOperation, identifier)
}

func formVerifCodePoolRedisKey(operation int, identifier string) string {
	redisRepresentationOfOperation := operationsAndRedisRepresentations[operation]
	return fmt.Sprintf(verifCodePoolKey, redisRepresentationOfOperation, identifier)
}

func formAccountBanTrackerKey(ip, accountID string) string {
	concatenatedIPAndAccountID := fmt.Sprintf("%s_%s", ip, accountID)
	return fmt.Sprintf(signInAccountBanTrackerKey, concatenatedIPAndAccountID)
}

func formAccountBanLimitKey(ip, accountID string) string {
	concatenatedIPAndAccountID := fmt.Sprintf("%s_%s", ip, accountID)
	return fmt.Sprintf(signAccountBanLimitKey, concatenatedIPAndAccountID)
}

func formSessionsOverflowStatusKey(ip, email string) string {
	concatenatedIPAndEmail := fmt.Sprintf("%s_%s", ip, email)
	return fmt.Sprintf(sessionsOverflowStatusKey, concatenatedIPAndEmail)
}

func formEmailCodeLimitKey(operation int, email string) string {
	redisRepresentationOfOperation := operationsAndRedisRepresentations[operation]
	return fmt.Sprintf(emailCodeLimitKey, redisRepresentationOfOperation, email)
}

func formEmailCodeTrackerKey(operation int, email string) string {
	redisRepresentationOfOperation := operationsAndRedisRepresentations[operation]
	return fmt.Sprintf(emailCodeTrackerKey, redisRepresentationOfOperation, email)
}

type signingUpUserHashMap struct {
	Email             string `redis:"email"`
	Nickname          string `redis:"nickname"`
	EncryptedPassword []byte `redis:"encrypted_password"`
}

type generalInMemoryStorage struct {
	client *redis.Client
}

func NewGeneralInMemoryStorage(client *redis.Client) *generalInMemoryStorage {
	return &generalInMemoryStorage{
		client: client,
	}
}

func (g *generalInMemoryStorage) DropErrIfNicknameReserved(ctx context.Context, nickname string) error {
	redisKey := fmt.Sprintf(reservedNicknameKey, nickname)

	err := g.client.Get(ctx, redisKey).Err()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}

		return errors.Wrap(err, "error occurred while reading reserved nickname")
	}

	return common.NewClientSideError("the provided nickname is already reserved")
}

func (g *generalInMemoryStorage) ReserveNickname(ctx context.Context, nickname string) error {
	redisKey := fmt.Sprintf(reservedNicknameKey, nickname)

	err := g.client.Set(ctx, redisKey, "1", expiration1Hour).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while reserving nickname")
	}

	return nil
}

func (g *generalInMemoryStorage) DeleteReservedNickname(ctx context.Context, nickname string) error {
	redisKey := fmt.Sprintf(reservedNicknameKey, nickname)

	err := g.client.Del(ctx, redisKey).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while deleting reserved nickname")
	}

	return nil
}

func (g *generalInMemoryStorage) ReadSigningUpUser(ctx context.Context, pipeID string) (*signingUpUser, error) {
	redisKey := fmt.Sprintf(signingUpUserKey, pipeID)

	var target signingUpUserHashMap

	err := g.client.HGetAll(ctx, redisKey).Scan(&target)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while getting signing up user")
	}

	return &signingUpUser{
		email:             target.Email,
		nickname:          target.Nickname,
		encryptedPassword: target.EncryptedPassword,
	}, nil
}

func (g *generalInMemoryStorage) InitSigningUpUser(ctx context.Context, pipeID string, user *signingUpUser) error {
	redisPipeline := g.client.TxPipeline()

	redisKey := fmt.Sprintf(signingUpUserKey, pipeID)

	signingUpUserRedisFormat := signingUpUserHashMap{
		Email:             user.email,
		Nickname:          user.nickname,
		EncryptedPassword: user.encryptedPassword,
	}

	redisPipeline.HSet(ctx, redisKey, signingUpUserRedisFormat)

	redisPipeline.Expire(ctx, redisKey, expiration1Hour)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		return errors.Wrap(err, "error occurred while creating new signing up user in transaction")
	}

	return nil
}

func (g *generalInMemoryStorage) UpdateSigningUpUser(ctx context.Context, pipeID string, user *signingUpUser) error {
	redisKey := fmt.Sprintf(signingUpUserKey, pipeID)

	signingUpUserRedisFormat := signingUpUserHashMap{
		Email:             user.email,
		Nickname:          user.nickname,
		EncryptedPassword: user.encryptedPassword,
	}

	err := g.client.HSet(ctx, redisKey, signingUpUserRedisFormat).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while updating signing up user")
	}

	return nil
}

func (g *generalInMemoryStorage) DeleteSigningUpUser(ctx context.Context, pipeID string) error {
	redisKey := fmt.Sprintf(signingUpUserKey, pipeID)

	err := g.client.Del(ctx, redisKey).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while deleting signing up user")
	}

	return nil
}

func (g *generalInMemoryStorage) SetCaptchaAnswer(ctx context.Context, captchaID, answer string) error {
	redisKey := fmt.Sprintf(captchaKey, captchaID)

	expiration := 10 * time.Minute
	err := g.client.Set(ctx, redisKey, answer, expiration).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while setting captcha")
	}

	return nil
}

func (g *generalInMemoryStorage) ReadCaptchaAnswer(ctx context.Context, id string) (string, error) {
	redisKey := fmt.Sprintf(captchaKey, id)

	val, err := g.client.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", common.NewClientSideError("captcha is not found")
		}

		return "", errors.Wrap(err, "error occurred while getting captcha")
	}

	return val, nil
}

func (g *generalInMemoryStorage) DeleteCaptchaAnswer(ctx context.Context, id string) error {
	redisKey := fmt.Sprintf(captchaKey, id)

	if err := g.client.Del(ctx, redisKey).Err(); err != nil {
		return errors.Wrap(err, "error occurred while deleting captcha")
	}

	return nil
}

func (g *generalInMemoryStorage) InitVerifCodePool(ctx context.Context, operation int, poolIdentifier, verifCode string) error {
	redisPipeline := g.client.TxPipeline()

	redisKey := formVerifCodePoolRedisKey(operation, poolIdentifier)

	redisPipeline.SAdd(ctx, redisKey, verifCode)

	redisPipeline.Expire(ctx, redisKey, expiration1Hour)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		return errors.Wrap(err, "error occurred while initializing verification code pool")
	}

	return nil
}

func (g *generalInMemoryStorage) DoesVerifCodePoolExist(ctx context.Context, operation int, poolIdentifier string) (bool, error) {
	redisKey := formVerifCodePoolRedisKey(operation, poolIdentifier)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of a key")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) AddVerifCodeToPool(ctx context.Context,
	operation int, poolIdentifier string, verifCode string,
) error {
	redisKey := formVerifCodePoolRedisKey(operation, poolIdentifier)

	err := g.client.SAdd(ctx, redisKey, verifCode).Err()
	if err != nil {
		return errors.Wrap(err, "errors occurred while adding verification code to pool")
	}

	return nil
}

func (g *generalInMemoryStorage) IsMemberOfVerifCodePool(ctx context.Context, operation int, poolIdentifier, code string) (bool, error) {
	redisKey := formVerifCodePoolRedisKey(operation, poolIdentifier)

	result, err := g.client.SIsMember(ctx, redisKey, code).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking membership in verif code pool")
	}

	return result, nil
}

func (g *generalInMemoryStorage) DeleteVerifCodePool(ctx context.Context, operation int, poolIdentifier string) error {
	redisKey := formVerifCodePoolRedisKey(operation, poolIdentifier)

	if err := g.client.Del(ctx, redisKey).Err(); err != nil {
		return errors.Wrap(err, "error occurred while deleting password reset pool")
	}

	return nil
}

func (g *generalInMemoryStorage) SetTimeoutForEmailCode(
	ctx context.Context, operation int, identifier string) error {
	redisKey := formTimeoutKey(operation, identifier)

	expiration := 1 * time.Minute

	err := g.client.Set(ctx, redisKey, "1", expiration).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while setting timeout for email code")
	}

	return nil
}

func (g *generalInMemoryStorage) IsTimeoutForEmailCode(ctx context.Context, operation int, identifier string) (bool, error) {
	redisKey := formTimeoutKey(operation, identifier)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}

	return redisKeyExists == result, nil
}

func (g *generalInMemoryStorage) DeleteTimeoutForEmailCode(ctx context.Context, operation int, identifier string) error {
	redisKey := formTimeoutKey(operation, identifier)

	err := g.client.Del(ctx, redisKey).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while deleting timeout for email code")
	}

	return nil
}

func (g *generalInMemoryStorage) SetGlobalBanAndDelGlobalBanTracker(ctx context.Context, ip string) error {
	redisPipeline := g.client.TxPipeline()

	redisKeyGlobalBanLimit := fmt.Sprintf(signInGlobalBanLimitKey, ip)

	randExpirationInRange, err := common.RandomIntegerSecure(15, 20)
	if err != nil {
		return err
	}

	expiration := time.Duration(randExpirationInRange) * time.Minute

	redisPipeline.Set(ctx, redisKeyGlobalBanLimit, "1", expiration)

	redisKeyBanTracker := fmt.Sprintf(signInGlobalBanTrackerKey, ip)

	redisPipeline.Del(ctx, redisKeyBanTracker)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		errWrappingMsg := "error occurred while performing following operations in txn: 1) Setting global ban limit; " +
			"2) Deleting global ban tracker"
		return errors.Wrap(err, errWrappingMsg)
	}

	return nil
}

func (g *generalInMemoryStorage) SetCaptchaLimitAndResetCaptchaTracker(ctx context.Context, accountID string, captchaTrackerResetVal int) error {
	redisPipeline := g.client.TxPipeline()

	redisKeyCaptchaLimit := fmt.Sprintf(signInCaptchaLimitKey, accountID)

	redisPipeline.Set(ctx, redisKeyCaptchaLimit, "1", expiration1Day)

	redisKeyCaptchaTracker := fmt.Sprintf(signInCaptchaTrackerKey, accountID)
	redisPipeline.Set(ctx, redisKeyCaptchaTracker, captchaTrackerResetVal, redis.KeepTTL)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		errWrappingMsg := "error occurred while performing following operations in txn: 1) Setting captcha limit; " +
			"2) Deleting sign in captcha tracker"
		return errors.Wrap(err, errWrappingMsg)
	}

	return nil
}

func (g *generalInMemoryStorage) DeleteSignInCaptchaLimit(ctx context.Context, accountID string) error {
	redisKeyCaptchaLimit := fmt.Sprintf(signInCaptchaLimitKey, accountID)

	_, err := g.client.Del(ctx, redisKeyCaptchaLimit).Result()
	if err != nil {
		return errors.Wrap(err, "error occurred while deleting sign in captcha limit")
	}

	return nil
}

func (g *generalInMemoryStorage) SetAccountBanAndDelAccountBanTracker(ctx context.Context, ip, accountID string) error {
	redisPipeline := g.client.TxPipeline()

	redisKeyAccountBanLimit := formAccountBanLimitKey(ip, accountID)

	randExpirationInRange, err := common.RandomIntegerSecure(30, 40)
	if err != nil {
		return err
	}

	expiration := time.Duration(randExpirationInRange) * time.Minute

	redisPipeline.Set(ctx, redisKeyAccountBanLimit, "1", expiration)

	redisKeyAccountBanTracker := formAccountBanTrackerKey(ip, accountID)

	redisPipeline.Del(ctx, redisKeyAccountBanTracker)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		errWrappingMsg := "error occurred while performing following operations in txn: 1) Setting account ban limit; " +
			"2) Deleting account ban tracker"
		return errors.Wrap(err, errWrappingMsg)
	}

	return nil
}

func (g *generalInMemoryStorage) IsSignInGlobalBan(ctx context.Context, ip string) (bool, error) {
	redisKey := fmt.Sprintf(signInGlobalBanLimitKey, ip)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of sign in global ban")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) IsSignInAccountBan(ctx context.Context, ip, accountID string) (bool, error) {
	redisKey := formAccountBanLimitKey(ip, accountID)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of sign in account ban")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) IsSignInCaptcha(ctx context.Context, accountID string) (bool, error) {
	redisKey := fmt.Sprintf(signInCaptchaLimitKey, accountID)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of sign in captcha")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) DoesCaptchaTrackerExist(ctx context.Context, accountID string) (bool, error) {
	redisKey := fmt.Sprintf(signInCaptchaTrackerKey, accountID)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of captcha tracker")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) DoesGlobalBanTrackerExist(ctx context.Context, ip string) (bool, error) {
	redisKey := fmt.Sprintf(signInGlobalBanTrackerKey, ip)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of global ban tracker")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) DoesAccountBanTrackerExist(ctx context.Context, ip, accountID string) (bool, error) {
	redisKey := formAccountBanTrackerKey(ip, accountID)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of account ban tracker")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) InitCaptchaTracker(ctx context.Context, accountID string, initialVal int) error {
	redisKey := fmt.Sprintf(signInCaptchaTrackerKey, accountID)

	err := g.client.Set(ctx, redisKey, initialVal, expiration1Hour).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while initializing captcha tracker")
	}

	return nil
}

func (g *generalInMemoryStorage) InitGlobalBanTracker(ctx context.Context, ip, accountID string) error {
	redisPipeline := g.client.TxPipeline()

	redisKey := fmt.Sprintf(signInGlobalBanTrackerKey, ip)

	redisPipeline.SAdd(ctx, redisKey, accountID)
	redisPipeline.Expire(ctx, redisKey, expiration1Hour)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		return errors.Wrap(err, "error occurred while initializing global ban tracker")
	}

	return nil
}

func (g *generalInMemoryStorage) InitAccountBanTracker(ctx context.Context, ip, accountID string, initialValue int) error {
	redisKey := formAccountBanTrackerKey(ip, accountID)

	err := g.client.Set(ctx, redisKey, initialValue, expiration1Hour).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while initializing account ban tracker")
	}

	return nil
}

func (g *generalInMemoryStorage) ReadGlobalBanTracker(ctx context.Context, ip string) ([]string, error) {
	redisKey := fmt.Sprintf(signInGlobalBanTrackerKey, ip)

	globalBanTracker, err := g.client.SMembers(ctx, redisKey).Result()
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while getting global ban tracker")
	}

	return globalBanTracker, nil
}

func (g *generalInMemoryStorage) ReadCaptchaTracker(ctx context.Context, accountID string) (int, error) {
	redisKey := fmt.Sprintf(signInCaptchaTrackerKey, accountID)

	resultAsString, err := g.client.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, errors.Wrap(err, "error occurred while getting sign in tracker fo captcha")
	}

	resultAsInt, err := strconv.Atoi(resultAsString)
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while casting string to integer (sign in tracker for captcha)")
	}

	return resultAsInt, nil
}

func (g *generalInMemoryStorage) ReadAccountBanTracker(ctx context.Context, ip, accountID string) (int, error) {
	redisKey := formAccountBanTrackerKey(ip, accountID)

	accountBanTracker, err := g.client.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, errors.Wrap(err, "error occurred while getting account ban tracker")
	}

	accountBanTrackerAsInt, err := strconv.Atoi(accountBanTracker)
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while converting account ban tracker(string) to integer")
	}

	return accountBanTrackerAsInt, nil
}

func (g *generalInMemoryStorage) UpdateTrackersForSignIn(ctx context.Context, ip, accountID string) error {
	redisPipeline := g.client.TxPipeline()

	redisKeyCaptchaTracker := fmt.Sprintf(signInCaptchaTrackerKey, accountID)
	redisPipeline.Incr(ctx, redisKeyCaptchaTracker)

	redisKeyGlobalBanTracker := fmt.Sprintf(signInGlobalBanTrackerKey, ip)
	redisPipeline.SAdd(ctx, redisKeyGlobalBanTracker, accountID)

	redisKeyAccountBanTracker := formAccountBanTrackerKey(ip, accountID)
	redisPipeline.Incr(ctx, redisKeyAccountBanTracker)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		return errors.Wrap(err, "error occurred while updating sign in trackers")
	}

	return nil
}

func (g *generalInMemoryStorage) DoesSessionsOverflowPoolExist(ctx context.Context, ip, email string) (bool, error) {
	redisKey := formSessionsOverflowStatusKey(ip, email)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of sessions overflow pool")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) InitSessionsOverflowStatus(ctx context.Context, ip, email, pipeID string) error {
	redisKey := formSessionsOverflowStatusKey(ip, email)

	err := g.client.Set(ctx, redisKey, pipeID, expiration1Hour).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while initializing sess")
	}

	return nil
}

func (g *generalInMemoryStorage) ReadSessionsOverflowStatus(ctx context.Context, ip, email string) (string, error) {
	redisKey := formSessionsOverflowStatusKey(ip, email)

	pipeID, err := g.client.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", common.NewClientSideError("sessions overflow status does not exist")
		}

		return "", errors.Wrap(err, "error occurred while checking membership for sessions overflow pool")
	}

	return pipeID, nil
}

func (g *generalInMemoryStorage) IsBanForEmailCode(ctx context.Context, operation int, email string) (bool, error) {
	redisKey := formEmailCodeLimitKey(operation, email)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of ban for email code sending")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) InitEmailCodeTracker(ctx context.Context, operation int, email string, initialValue int) error {
	redisKey := formEmailCodeTrackerKey(operation, email)

	err := g.client.Set(ctx, redisKey, initialValue, expiration30Mins).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while initializing email code tracker")
	}

	return nil
}

func (g *generalInMemoryStorage) ReadEmailCodeTracker(ctx context.Context, operation int, email string) (int, error) {
	redisKey := formEmailCodeTrackerKey(operation, email)

	emailCodeTracker, err := g.client.Get(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		errMsg := fmt.Sprintf("error occurred while getting email code tracker (%s)",
			operationsAndRedisRepresentations[operation])
		return 0, errors.Wrap(err, errMsg)
	}

	emailCodeTrackerAsInt, err := strconv.Atoi(emailCodeTracker)
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while converting account ban tracker(string) to integer")
	}

	return emailCodeTrackerAsInt, nil
}

func (g *generalInMemoryStorage) UpdateEmailCodeTracker(ctx context.Context, operation int, email string) error {
	redisKey := formEmailCodeTrackerKey(operation, email)

	err := g.client.Incr(ctx, redisKey).Err()
	if err != nil {
		errMsg := fmt.Sprintf(
			"error occurred while updating email code tracker (%s)",
			operationsAndRedisRepresentations[operation])

		return errors.Wrap(err, errMsg)
	}

	return nil
}

func (g *generalInMemoryStorage) DoesEmailCodeTrackerExist(ctx context.Context, operation int, email string) (bool, error) {
	redisKey := formEmailCodeTrackerKey(operation, email)

	result, err := g.client.Exists(ctx, redisKey).Result()
	if err != nil {
		return false, errors.Wrap(err, "error occurred while checking existence of email code tracker")
	}

	return result == redisKeyExists, nil
}

func (g *generalInMemoryStorage) SetBanForEmailCodeAndDelEmailCodeTracker(ctx context.Context, operation int, email string) error {
	redisPipeline := g.client.TxPipeline()

	redisKeyEmailCodeLimit := formEmailCodeLimitKey(operation, email)

	redisPipeline.Set(ctx, redisKeyEmailCodeLimit, "1", expiration30Mins)

	redisKeyEmailCodeTracker := formEmailCodeTrackerKey(operation, email)
	redisPipeline.Del(ctx, redisKeyEmailCodeTracker)

	if _, err := redisPipeline.Exec(ctx); err != nil {
		errMsg := fmt.Sprintf("error occurred while performing multiple actions in txn: "+
			"1) Setting email code limit; "+
			"2) Deleting email code tracker %s", operationsAndRedisRepresentations[operation])

		return errors.Wrap(err, errMsg)
	}

	return nil
}

func (g *generalInMemoryStorage) DeleteSessionsOverflowStatus(ctx context.Context, ip, email string) error {
	redisKey := formSessionsOverflowStatusKey(ip, email)

	err := g.client.Del(ctx, redisKey).Err()
	if err != nil {
		return errors.Wrap(err, "error occurred while deleting sessions overflow status")
	}

	return nil
}
