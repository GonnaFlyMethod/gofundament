package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

const (
	jwtIssuer = "gofundament.auth"

	refreshTokenPrivateKeyPath = "auth-refresh-private.pem" //nolint:gosec
	refreshTokenPublicKeyPath  = "auth-refresh-public.pem"  //nolint:gosec
	accessTokenPrivateKeyPath  = "auth-access-private.pem"  //nolint:gosec
	accessTokenPublicKeyPath   = "auth-access-public.pem"   //nolint:gosec

	refreshTokenType = "refresh"
	accessTokenType  = "access"

	accessTokenDuration = 1 * time.Minute
)

type KeyReader interface {
	ReadPublicKeyRefreshToken() ([]byte, error)
	ReadPrivateKeyRefreshToken() ([]byte, error)
	ReadPublicKeyAccessToken() ([]byte, error)
	ReadPrivateKeyAccessToken() ([]byte, error)
}

var FileKeyReader = DefaultKeyReader{}

type DefaultKeyReader struct{}

func (dkr DefaultKeyReader) ReadPublicKeyRefreshToken() ([]byte, error) {
	verifyBytes, err := os.ReadFile(refreshTokenPublicKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Can't read file with refresh token public key")
	}

	return verifyBytes, nil
}

func (dkr DefaultKeyReader) ReadPrivateKeyRefreshToken() ([]byte, error) {
	signBytes, err := os.ReadFile(refreshTokenPrivateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "can't read file that contains private RSA key for refresh token")
	}

	return signBytes, nil
}

func (dkr DefaultKeyReader) ReadPublicKeyAccessToken() ([]byte, error) {
	verifyBytes, err := os.ReadFile(accessTokenPublicKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Can't read file with access token public key")
	}

	return verifyBytes, nil
}

func (dkr DefaultKeyReader) ReadPrivateKeyAccessToken() ([]byte, error) {
	signBytes, err := os.ReadFile(accessTokenPrivateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "can't read file that contains private RSA key for access token")
	}

	return signBytes, nil
}

type refreshTokenClaims struct {
	AccountID string
	TokenType string
	SessionID string
	jwt.StandardClaims
}

func getRefreshTokenClaims(accountID, sessionID string) *refreshTokenClaims {
	return &refreshTokenClaims{
		accountID,
		refreshTokenType,
		sessionID,
		jwt.StandardClaims{
			Issuer: jwtIssuer,
		},
	}
}

func GenerateRefreshToken(accountID, sessionID string, keyReader KeyReader) (string, error) {
	claims := getRefreshTokenClaims(accountID, sessionID)

	signBytes, err := keyReader.ReadPrivateKeyRefreshToken()
	if err != nil {
		return "", err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return "", errors.Wrap(err, "can't parse RSA private key for refresh token")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func ValidateRefreshToken(tokenString string, keyReader KeyReader) (string, string, error) { //nolint:gocritic
	token, err := jwt.ParseWithClaims(tokenString, &refreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method for refresh token")
		}

		verifyBytes, err := keyReader.ReadPublicKeyRefreshToken()
		if err != nil {
			return nil, errors.Wrap(err, "Can't read file with refresh token public key")
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return nil, errors.Wrap(err, "Can't parse RSA public key for refresh token")
		}

		return verifyKey, nil
	})
	if err != nil {
		var jwtValidationError *jwt.ValidationError

		// TODO: consider using errors.Is()
		if errors.As(err, &jwtValidationError) {
			log.Error().Err(err).Msg("jwt validation error (refresh token)")
			return "", "", common.NewClientSideError("Invalid token: authentication failed")
		}

		return "", "", err
	}

	claims, ok := token.Claims.(*refreshTokenClaims)
	if !ok || !token.Valid || claims.AccountID == "" || claims.SessionID == "" || claims.TokenType != refreshTokenType {
		return "", "", common.NewClientSideError("Invalid token: authentication failed")
	}

	return claims.AccountID, claims.SessionID, nil
}

type accessTokenClaims struct {
	AccountID string
	TokenType string
	jwt.StandardClaims
}

func newAccessTokenClaims(accountID string) *accessTokenClaims {
	return &accessTokenClaims{
		accountID,
		accessTokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(accessTokenDuration).Unix(),
			Issuer:    jwtIssuer,
		},
	}
}

func GenerateAccessToken(accountID string, keyReader KeyReader) (string, error) {
	claims := newAccessTokenClaims(accountID)

	signBytes, err := keyReader.ReadPrivateKeyAccessToken()
	if err != nil {
		return "", err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return "", errors.Wrap(err, "Can't parse RSA private key for access token")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

func ValidateAccessToken(tokenString string, keyReader KeyReader) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method in access token")
		}

		verifyBytes, err := keyReader.ReadPublicKeyAccessToken()
		if err != nil {
			return nil, errors.Wrap(err, "Can't read file with access token public key")
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return nil, errors.Wrap(err, "Can't parse RSA public key for access token")
		}

		return verifyKey, nil
	})
	if err != nil {
		var jwtValidationError *jwt.ValidationError

		if errors.As(err, &jwtValidationError) {
			log.Error().Err(err).Msg("jwt validation error (access token)")
			return "", common.NewClientSideError("Invalid token: authentication failed")
		}

		return "", err
	}

	claims, ok := token.Claims.(*accessTokenClaims)
	if !ok || !token.Valid || claims.AccountID == "" || claims.TokenType != accessTokenType {
		return "", common.NewClientSideError("Invalid token: authentication failed")
	}

	return claims.AccountID, nil
}

type TokensPair struct {
	AccessToken, RefreshToken string
}

func GenerateTokensPair(accountID, sessionID string, keyReader KeyReader) (string, string, error) { //nolint:gocritic
	accessToken, err := GenerateAccessToken(accountID, keyReader)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateRefreshToken(accountID, sessionID, keyReader)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
