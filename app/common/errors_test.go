package common

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientSideErrorMarshaling(t *testing.T) {
	const errTitle = "some error"
	expectedJSON := fmt.Sprintf(`{"title":%q}`, errTitle)

	err := NewClientSideError(errTitle)
	actual, err := json.Marshal(err)

	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, string(actual))
}

func TestValidationErrorMarshaling(t *testing.T) {
	err := NewValidationError(
		"validation error",
		[]string{"some error", "some other error"},
	)

	expectedJSON := `{"title":"validation error","errors":["some error","some other error"]}`

	actual, err := json.Marshal(err)

	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, string(actual))
}
