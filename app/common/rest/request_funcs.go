package rest

import (
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/GonnaFlyMethod/gofundament/app/common"
)

// BindAndValidate TODO: if a json field has wrong type comparing to GO lang struct
// then the func below throws error like:
// json: cannot unmarshal bool into Go struct field UpdatePasswordRequest.feel_like_get_hacked of type string
// it should be replaced by error "invalid type of field"
func BindAndValidate(request *http.Request, target any) error {
	if err := render.DecodeJSON(request.Body, target); err != nil {
		return common.NewClientSideError(err.Error())
	}

	if err := GetValidator().Struct(target); err != nil {
		//nolint:errorlint
		if err, ok := err.(validator.ValidationErrors); ok {
			return GetValidationError(err)
		}

		return err
	}

	return nil
}

func GetUUIDFromPath(r *http.Request) (string, error) {
	id := chi.URLParam(r, "id")

	if _, err := uuid.Parse(id); err != nil {
		return "", common.NewValidationError("Validation error", []string{"UUID must be correct"})
	}
	return id, nil
}

func GetNicknameFromPath(r *http.Request) (string, error) {
	nickname := chi.URLParam(r, "nickname")

	if _, err := ValidateNickname(nickname); err != nil {
		return "", err
	}
	return nickname, nil
}

func GetEmailFromURL(r *http.Request) (string, error) {
	emailFromQuery := r.URL.Query().Get("email")
	wrappedMail := struct {
		Email string `validate:"required,email"`
	}{Email: emailFromQuery}

	if err := GetValidator().Struct(wrappedMail); err != nil {
		var errs validator.ValidationErrors
		if ok := errors.As(err, &errs); ok {
			return "", GetValidationError(errs)
		}
		return "", errors.Wrap(err, "Unexpected error while receiving email")
	}

	return emailFromQuery, nil
}

func GetNicknameFromURL(r *http.Request) (string, error) {
	nicknameFromQuery := r.URL.Query().Get("nickname")

	if _, err := ValidateNickname(nicknameFromQuery); err != nil {
		return "", err
	}

	return nicknameFromQuery, nil
}

func ValidateNickname(nickname string) (bool, error) {
	wrappedNickname := struct {
		Nickname string `validate:"required,lte=20,alphanum"`
	}{Nickname: nickname}

	if err := GetValidator().Struct(wrappedNickname); err != nil {
		var errs validator.ValidationErrors
		if ok := errors.As(err, &errs); ok {
			return false, GetValidationError(errs)
		}
		return false, errors.Wrap(err, "Unexpected error while checking nickname")
	}

	return true, nil
}

func GetAccountIDFromJWT(r *http.Request) (string, error) {
	id := r.Context().Value(UserIDCtx{})

	if id, ok := id.(string); ok {
		return id, nil
	}

	return "", errors.New("error has occurred while trying to get ID from JWT")
}

// TODO: investigate the true source of ip

//nolint:nestif
func GetRealIP(r *http.Request) (string, error) {
	var ip string

	if tcip := r.Header.Get("True-Client-IP"); tcip != "" {
		ip = tcip
	} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		i := strings.Index(xff, ", ")
		if i == -1 {
			i = len(xff)
		}
		ip = xff[:i]
	} else {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
	}

	return canonicalizeIP(ip), nil
}

// canonicalizeIP returns a form of ip suitable for comparison to other IPs.
// For IPv4 addresses, this is simply the whole string.
// For IPv6 addresses, this is the /64 prefix.

//nolint:gosimple
func canonicalizeIP(ip string) string {
	isIPv6 := false
	// This is how net.ParseIP decides if an address is IPv6
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.7:src/net/ip.go;l=704
	for i := 0; !isIPv6 && i < len(ip); i++ {
		switch ip[i] {
		case '.':
			// IPv4
			return ip
		case ':':
			// IPv6
			isIPv6 = true
			break
		}
	}
	if !isIPv6 {
		// Not an IP address at all
		return ip
	}

	ipv6 := net.ParseIP(ip)
	if ipv6 == nil {
		return ip
	}

	return ipv6.Mask(net.CIDRMask(64, 128)).String()
}
