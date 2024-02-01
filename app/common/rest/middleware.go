package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest/auth"
)

func IsJSONMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}

		rBody, err := io.ReadAll(r.Body)
		if err != nil {
			WriteErrorResponse(r.Context(), err, w, nil)
			return
		}

		if !json.Valid(rBody) {
			err = common.NewClientSideError("request body is not a valid JSON")
			WriteErrorResponse(r.Context(), err, w, nil)
			return
		}

		buffer := bytes.NewBuffer(rBody)
		r.Body = io.NopCloser(buffer)

		next.ServeHTTP(w, r)
	})
}

type UserIDCtx struct{}

func AccessTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token, err := extractToken(r)
		if err != nil {
			WriteErrorResponse(ctx, err, w, nil)
			return
		}

		userID, err := auth.ValidateAccessToken(token, auth.FileKeyReader)
		if err != nil {
			WriteErrorResponse(ctx, err, w, nil)
			return
		}

		newCtx := context.WithValue(r.Context(), UserIDCtx{}, userID)
		r = r.WithContext(newCtx)

		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	authHeaderContent := strings.Split(authHeader, " ")

	if len(authHeaderContent) != 2 {
		return "", common.NewClientSideError("Token not provided or malformed")
	}

	return authHeaderContent[1], nil
}
