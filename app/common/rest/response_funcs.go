package rest

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

func WriteErrorResponse(ctx context.Context, errorResponse error, writer http.ResponseWriter,
	meta map[string]interface{}) {
	var statusCode int

	var (
		clientSideError *common.ClientSideError
		validationError *common.ValidationError
		tooManyRequests *common.TooManyRequestsError
	)

	switch {
	case errors.As(errorResponse, &clientSideError) || errors.As(errorResponse, &validationError):
		statusCode = http.StatusUnprocessableEntity
	case errors.As(errorResponse, &tooManyRequests):
		statusCode = http.StatusTooManyRequests
	default:
		zerolog.Ctx(ctx).Error().Err(errorResponse).Msg("error has occurred while trying to process HTTP request")
		statusCode = http.StatusInternalServerError
		errorResponse = common.NewServerSideError("something went wrong on our side")
	}

	responseBody, err := json.Marshal(errorResponse)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(errorResponse).Msg("error has occurred while trying to marshal client error")
		return
	}

	// TODO: this is temporary unmarshalling until universal error format is not implemented
	if len(meta) > 0 {
		var target map[string]interface{}

		err := json.Unmarshal(responseBody, &target)
		if err != nil {
			WriteErrorResponse(ctx, err, writer, nil)
			return
		}

		target["meta"] = meta

		responseBodyWithMeta, err := json.Marshal(target)
		if err != nil {
			WriteErrorResponse(ctx, err, writer, nil)
			return
		}

		responseBody = responseBodyWithMeta
	}

	WriteResponse(ctx, responseBody, statusCode, writer)
}

func WriteResponse(ctx context.Context, body []byte, statusCode int, writer http.ResponseWriter) {
	writer.WriteHeader(statusCode)

	if _, err := writer.Write(body); err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("error has occurred while trying to write HTTP response")
	}
}
