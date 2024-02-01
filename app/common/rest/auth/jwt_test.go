package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

func Test_GenerateRefreshToken(t *testing.T) {
	mockKeyReader := MockKeyReader{}

	const (
		userID   = "0184edeb-a9ff-55f1-0e6b-4a771d418e5e"
		tokenKey = "cQkpsvMYeMNNxIMgmblc2XujBLZ8yNjFIIjWU5Vvenc" //nolint:gosec
	)

	refreshToken, err := GenerateRefreshToken(userID, tokenKey, mockKeyReader)

	assert.NotEmpty(t, refreshToken)
	assert.NoError(t, err)
}

func Test_GenerateAccessToken(t *testing.T) {
	mockKeyReader := MockKeyReader{}

	const userID = "0184edeb-a9ff-55f1-0e6b-4a771d418e5e"

	accessToken, err := GenerateAccessToken(userID, mockKeyReader)

	assert.NotEmpty(t, accessToken)
	assert.NoError(t, err)
}

func Test_ValidateRefreshToken(t *testing.T) {
	mockKeyReader := MockKeyReader{}

	const (
		userID   = "0184edeb-a9ff-55f1-0e6b-4a771d418e5e"
		tokenKey = "cQkpsvMYeMNNxIMgmblc2XujBLZ8yNjFIIjWU5Vvenc" //nolint:gosec
	)

	accessToken, err := GenerateAccessToken(userID, mockKeyReader)
	assert.NoError(t, err)

	refreshToken, err := GenerateRefreshToken(userID, tokenKey, mockKeyReader)
	assert.NoError(t, err)

	testCases := []struct {
		name string

		refreshToken string
		shouldGetErr bool
	}{
		{
			name:         "valid refresh token",
			refreshToken: refreshToken,
			shouldGetErr: false,
		},
		{
			name: "access token instead of refresh token",

			refreshToken: accessToken,
			shouldGetErr: true,
		},
		{
			name:         "invalid refresh token",
			refreshToken: "testbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwb3J0Zm9saW8uYXV0aCJ9.c5rpL2G_PQX9jvjF4OVWX-tfDRy9Rrfsar6e4gxyGnlEbJjKx7_j4N1S0gSmV4OjbNuWl5HPTcWhE-xBatguhBBSJ4fd3awc9EY_KxEhfICp-Gy7RmeP5TcZuLUdMpzoaZKkQ9_wAUNq4oOt82TVtn3l6sunBJf16DTW-o9B7VsH9GYjcHgI8lG3A3QTD5RRAxYZF8S8wq8Gb1sLuiXSJE_AFGZge1IPgwMPrLw9wDS3I3UzPcGm24XkbAv3euL3QIggQPv1TAJloZi_dNAOkDFkPzFQxh1QktqSqe0v9Gxf4pTFOEp-Su6aebI46cOtGyaAIfzd4puKTb1UwpN89g",
			shouldGetErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualUserID, actualTokenKey, err := ValidateRefreshToken(tc.refreshToken, mockKeyReader)

			if tc.shouldGetErr {
				assert.Empty(t, actualUserID)
				assert.Empty(t, actualTokenKey)
				common.AssertClientSideError(t, err)

				return
			}

			assert.NotEmpty(t, actualUserID)
			assert.NotEmpty(t, actualTokenKey)
			assert.NoError(t, err)
		})
	}
}

func Test_validateAccessToken(t *testing.T) {
	mockKeyReader := MockKeyReader{}

	const (
		userID   = "0184edeb-a9ff-55f1-0e6b-4a771d418e5e"
		tokenKey = "cQkpsvMYeMNNxIMgmblc2XujBLZ8yNjFIIjWU5Vvenc" //nolint:gosec
	)

	accessToken, err := GenerateAccessToken(userID, mockKeyReader)
	assert.NoError(t, err)

	refreshToken, err := GenerateRefreshToken(userID, tokenKey, mockKeyReader)
	assert.NoError(t, err)

	testCases := []struct {
		name string

		accessToken  string
		shouldGetErr bool
		errChecker   func(err error)
	}{
		{
			name: "valid access token",

			accessToken:  accessToken,
			shouldGetErr: false,
		},
		{
			name: "refresh token instead of access token",

			accessToken:  refreshToken,
			shouldGetErr: true,
		},
		{
			name:         "invalid access token",
			accessToken:  "testSGTc43JBVutyeewszEXgUAmSHY2DGtu1lv7p2zd9OTAv0V3xaD7Pnau4REXfUwdg6NwDcvsh6bcRdIzwlWAq7Q8pmQpqgNv7Ty1ZQI05Y_A5Z9B8dhJWjtRfg",
			shouldGetErr: true,
		},
		{
			name:         "expired access token",
			accessToken:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySUQiOiIwMTg0ZWRlYi1hOWZmLTU1ZjEtMGU2Yi00YTc3MWQ0MThlNWUiLCJUb2tlblR5cGUiOiJhY2Nlc3MiLCJleHAiOjE2NzM3ODM2MjUsImlzcyI6InBvcnRmb2xpby5hdXRoIn0.ucAU94ph1ss6xoS8g7N9VYUUVSXg3Zq1tDxaJj8Thiv2Pkekat6h4T-SI6Z-F_Tc0ZUCNO_mOMXEV1zAQ1AhZb_tor8lKqS7KJuJ3r62bLK5qr7s9b6R1Wm4OecmIK2Vhc6tWRgmxS7S4bPSvM7J0HxMF2eANkmPv0RfnqN-R6EMzDurc5BWJUSbgfQVHQsm-o6woJKkAZ2SGbWqxOeTlhKQLv6R-SGTc43JBVutyeewszEXgUAmSHY2DGtu1lv7p2zd9OTAv0V3xaD7Pnau4REXfUwdg6NwDcvsh6bcRdIzwlWAq7Q8pmQpqgNv7Ty1ZQI05Y_A5Z9B8dhJWjtRfg",
			shouldGetErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualAccountID, err := ValidateAccessToken(tc.accessToken, mockKeyReader)

			if tc.shouldGetErr {
				assert.Empty(t, actualAccountID)
				common.AssertClientSideError(t, err)
				return
			}

			assert.NotEmpty(t, actualAccountID)
			assert.NoError(t, err)
		})
	}
}
