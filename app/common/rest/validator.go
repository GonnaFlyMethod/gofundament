package rest

import (
	"math"
	"unicode"
	"unicode/utf8"

	et "github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	envalidator "github.com/go-playground/validator/v10/translations/en"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/enums"
)

var (
	validate   *validator.Validate
	translator ut.Translator
)

func GetValidator() *validator.Validate {
	return validate
}

func GetValidationError(errs validator.ValidationErrors) error {
	validationErrors := errs.Translate(translator)
	details := make([]string, 0)

	for _, err := range validationErrors {
		details = append(details, err)
	}
	return common.NewValidationError(
		"Validation Error",
		details,
	)
}

func init() {
	validate = validator.New()

	en := et.New()
	uni := ut.New(en, en)

	translator, _ = uni.GetTranslator("en")
	if err := envalidator.RegisterDefaultTranslations(validate, translator); err != nil {
		panic(err)
	}

	if err := registerValidation(
		validate,
		translator,
		"country",
		"Invalid country code passed into {0}",
		countryValidator,
	); err != nil {
		panic(err)
	}

	if err := registerValidation(
		validate,
		translator,
		"password",
		"Unsuitable password passed into {0}",
		passwordValidator,
	); err != nil {
		panic(err)
	}
}

func countryValidator(fieldLevel validator.FieldLevel) bool {
	targetToCheck := fieldLevel.Field().String()

	for _, countryCode := range enums.Countries {
		if countryCode == targetToCheck {
			return true
		}
	}

	return false
}

func passwordValidator(fieldLevel validator.FieldLevel) bool {
	targetToCheck := fieldLevel.Field().String()

	isSuitableContent := isSuitableContentOfPassword(targetToCheck)
	if !isSuitableContent {
		return false
	}

	passwordEntropy := calculatePasswordEntropy(targetToCheck)

	// TODO: checking password's entropy is first barrier of dropping weak passwords additionally we 100% need
	// to check if password is in dictionary list of hacked passwords using rest of haveibeenpwned.com

	return passwordEntropy >= secureBitsThreshold
}

func isSuitableContentOfPassword(password string) bool {
	for i := 0; i < len(password); i++ {
		simpleRune := rune(password[i])

		if simpleRune > unicode.MaxASCII && !unicode.IsSymbol(simpleRune) && !unicode.IsDigit(simpleRune) {
			return false
		}
	}

	return true
}

const (
	secureBitsThreshold = 70.0

	// Base pool sizes
	digitsPool            = 10 // 0-9
	lowerCaseLatinLetters = 26 // a-z
	upperCaseLatinLetters = 26 // A-Z
	specialSymbols        = 32 // `~!@#$%^&*()-=_+[{]}\
)

func calculatePasswordEntropy(password string) float64 {
	poolSize := calculatePoolsSize(password)
	passwordLength := utf8.RuneCountInString(password)

	poolSizeConverted := float64(poolSize)
	passwordLengthConverted := float64(passwordLength)

	return passwordLengthConverted * math.Log2(poolSizeConverted)
}

func calculatePoolsSize(password string) int {
	actualPoolSizeAsBits := 0

	for _, r := range password {
		if unicode.IsDigit(r) {
			actualPoolSizeAsBits |= 0x01
		}

		if unicode.IsLetter(r) && unicode.IsLower(r) {
			actualPoolSizeAsBits |= 0x02
		}

		if unicode.IsLetter(r) && unicode.IsUpper(r) {
			actualPoolSizeAsBits |= 0x04
		}

		if unicode.IsSymbol(r) {
			actualPoolSizeAsBits |= 0x08
		}
	}

	maskEntropy := map[int]int{
		0x01: digitsPool,
		0x02: lowerCaseLatinLetters,
		0x04: upperCaseLatinLetters,
		0x08: specialSymbols,
	}

	calculatedPoolSize := 0

	for bit, poolSize := range maskEntropy {
		if bit&actualPoolSizeAsBits > 0 {
			calculatedPoolSize += poolSize
		}
	}

	return calculatedPoolSize
}

func registerValidation(
	validate *validator.Validate,
	translator ut.Translator,
	tag string,
	msg string,
	validatorFunc validator.Func,
) error {
	if err := validate.RegisterValidation(tag, validatorFunc); err != nil {
		return err
	}

	err := setErrorMessage(validate, translator, tag, msg)

	return err
}

func setErrorMessage(
	validate *validator.Validate,
	translator ut.Translator,
	tag string,
	msg string,
) error {
	return validate.RegisterTranslation(
		tag,
		translator,
		func(ut ut.Translator) error {
			return ut.Add(tag, msg, false)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(tag, fe.Field())
			return t
		},
	)
}
