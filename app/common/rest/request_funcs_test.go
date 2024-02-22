package rest

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

func TestGetUUIDFromPath(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Valid UUID",
			input:       "0184edeb-a9ff-55f1-0e6b-4a771d418e5e",
			expectError: false,
		},
		{
			name:        "Invalid UUID",
			input:       "invalid-uuid",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, &chi.Context{
				URLParams: chi.RouteParams{
					Keys:   []string{"id"},
					Values: []string{tc.input},
				},
			})
			r := new(http.Request).WithContext(ctx)

			id, err := GetUUIDFromPath(r)

			if tc.expectError {
				common.AssertValidationError(t, err)
			} else {
				assert.Equal(t, tc.input, id)
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetNicknameFromPath(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Valid nickname",
			input:       "nickname",
			expectError: false,
		},
		{
			name:        "Invalid nickname",
			input:       "invalid nickname",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), chi.RouteCtxKey, &chi.Context{
				URLParams: chi.RouteParams{
					Keys:   []string{"nickname"},
					Values: []string{tc.input},
				},
			})
			r := new(http.Request).WithContext(ctx)

			nickname, err := GetNicknameFromPath(r)

			if tc.expectError {
				common.AssertValidationError(t, err)
			} else {
				assert.Equal(t, tc.input, nickname)
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetEmailFromURL(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		isValid bool
	}{
		{
			name:    "Valid email",
			input:   "some@mail.com",
			isValid: true,
		},
		{
			name:    "Invalid email",
			input:   "invalid-email",
			isValid: false,
		},
		{
			name:    "Empty email",
			input:   "",
			isValid: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				URL: &url.URL{
					RawQuery: "email=" + tc.input,
				},
			}

			email, err := GetEmailFromURL(r)

			if tc.isValid {
				assert.Equal(t, tc.input, email)
				assert.NoError(t, err)
			} else {
				common.AssertValidationError(t, err)
			}
		})
	}
}

func TestGetNicknameFromURL(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		isValid bool
	}{
		{
			name:    "Valid nickname",
			input:   "nickname",
			isValid: true,
		},
		{
			name:    "Invalid nickname",
			input:   "!@#$%^&*()",
			isValid: false,
		},
		{
			name:    "Empty nickname",
			input:   "",
			isValid: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{
				URL: &url.URL{
					RawQuery: "nickname=" + tc.input,
				},
			}

			nickname, err := GetNicknameFromURL(r)

			if tc.isValid {
				assert.Equal(t, tc.input, nickname)
				assert.NoError(t, err)
			} else {
				common.AssertValidationError(t, err)
			}
		})
	}
}
