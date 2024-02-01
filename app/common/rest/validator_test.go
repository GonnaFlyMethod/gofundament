package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_calculatePasswordEntropy(t *testing.T) {
	testCases := []struct {
		password        string
		expectedEntropy float64
	}{
		{
			password:        "123456789",
			expectedEntropy: 29.89735285398626,
		},
		{
			password:        "incorrect",
			expectedEntropy: 42.303957463269825,
		},
		{
			password:        "INCORRECT",
			expectedEntropy: 42.303957463269825,
		},
		{
			password:        "~$%^@!%&*",
			expectedEntropy: 45,
		},
		{
			password:        "Incorrect",
			expectedEntropy: 51.303957463269825,
		},
		{
			password:        "IncoRRect77",
			expectedEntropy: 65.49615941425563,
		},
		{
			password:        "IncoRRect77$%&",
			expectedEntropy: 91.76424392348693,
		},
	}

	for _, tc := range testCases {
		t.Run("entropy should be calculate correctly", func(t *testing.T) {
			actualEntropy := calculatePasswordEntropy(tc.password)

			assert.Equal(t, tc.expectedEntropy, actualEntropy)
		})
	}
}

func Test_isSuitableContentOfPassword(t *testing.T) {
	testCases := []struct {
		password       string
		expectedResult bool
	}{
		{
			password:       "123456789",
			expectedResult: true,
		},
		{
			password:       "incorrect",
			expectedResult: true,
		},
		{
			password:       "INCORRECT",
			expectedResult: true,
		},
		{
			password:       "~$%^@!%&*",
			expectedResult: true,
		},
		{
			password:       "IncoRRect77",
			expectedResult: true,
		},
		{
			password:       "IncoRRect77$%&",
			expectedResult: true,
		},
		{
			password:       "日本語134パスワード__%!",
			expectedResult: false,
		},
		{
			password:       "2134Paris_cité_4",
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run("unsuitable passwords should be differentiated", func(t *testing.T) {
			actualResult := isSuitableContentOfPassword(tc.password)

			assert.Equal(t, tc.expectedResult, actualResult)
		})
	}
}
