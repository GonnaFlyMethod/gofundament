package common

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

// RandomIntegerSecure the returnable range is [inclusiveStart;inclusiveEnd]
func RandomIntegerSecure(inclusiveStart, inclusiveEnd int) (int, error) {
	if inclusiveStart >= inclusiveEnd {
		err := errors.New("inclusive start > or == incisive end (forbidden input for the func)")
		return 0, errors.Wrap(err, "error occurred while generating random integer")
	}

	rangeForGeneration := int64(inclusiveEnd+1) - int64(inclusiveStart)

	randomBigInt, err := rand.Int(rand.Reader, big.NewInt(rangeForGeneration))
	if err != nil {
		return 0, errors.Wrap(err, "error occurred while generating random integer")
	}

	randomBigIntAsInt64 := randomBigInt.Int64() + int64(inclusiveStart)

	return int(randomBigIntAsInt64), nil
}
