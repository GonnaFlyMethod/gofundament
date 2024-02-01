package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RandomIntegerSecure(t *testing.T) {
	testCases := []struct {
		name string

		inclusiveStart int
		inclusiveEnd   int

		shouldGerError bool
	}{
		{
			name: "should successfully generate integer from given range",

			inclusiveStart: 15,
			inclusiveEnd:   20,

			shouldGerError: false,
		},
		{
			name: "should get error because inclusiveStart == inclusiveEnd",

			inclusiveStart: 15,
			inclusiveEnd:   15,

			shouldGerError: true,
		},
		{
			name: "should get error because inclusiveStart > inclusiveEnd",

			inclusiveStart: 16,
			inclusiveEnd:   15,

			shouldGerError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := RandomIntegerSecure(tc.inclusiveStart, tc.inclusiveEnd)

			if tc.shouldGerError {
				assert.Error(t, err)
				assert.Empty(t, result)

				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, result)
		})
	}
}
