package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsJSONMiddleware(t *testing.T) {
	testCases := []struct {
		name string

		getBodyForRequest  func() *bytes.Reader
		expectedStatusCode int
	}{
		{
			name: "should return 200 because incoming json is valid (object)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`{"test":"valid"}`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusOK,
		},
		{
			name: "should return 200 because incoming json is valid (array)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`[1, 2, 3, 4]`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusOK,
		},
		{
			name: "should return 422 because incoming json is not valid (object)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`{"test": 1invalid_json}`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusUnprocessableEntity,
		},
		{
			name: "should return 422 because incoming json is not valid (array)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`[1, 2, 3, 4`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusUnprocessableEntity,
		},
		{
			name: "should return 422 because incoming json is not valid (string literal)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`"1"`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusOK,
		},
		{
			name: "should return 422 because incoming json is not valid (integer literal)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`100`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusOK,
		},
		{
			name: "should return 422 because incoming json is not valid (null)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(`null`)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusOK,
		},
		{
			name: "should return 422 because incoming json is not valid (empty request body)",

			getBodyForRequest: func() *bytes.Reader {
				body := []byte(``)
				return bytes.NewReader(body)
			},

			expectedStatusCode: http.StatusUnprocessableEntity,
		},
	}

	testHandler := func(writer http.ResponseWriter, request *http.Request) {}

	handlerBehindMiddleware := http.HandlerFunc(testHandler)
	middlewareChecks := IsJSONMiddleware(handlerBehindMiddleware)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			body := tc.getBodyForRequest()

			req := httptest.NewRequest(http.MethodPost, "http://testing.com", body)

			middlewareChecks.ServeHTTP(recorder, req)
			assert.Equal(t, tc.expectedStatusCode, recorder.Code)
		})
	}
}
