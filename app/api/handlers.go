package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/oapi-codegen/runtime/types"
	"github.com/pkg/errors"

	"github.com/GonnaFlyMethod/gofundament/app/common"
	"github.com/GonnaFlyMethod/gofundament/app/common/enums"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest"
	"github.com/GonnaFlyMethod/gofundament/app/common/rest/auth"
	"github.com/GonnaFlyMethod/gofundament/app/domain/account"
)

type Handler struct {
	accountService *account.Service
}

func NewHandler(accountService *account.Service) *Handler {
	return &Handler{
		accountService: accountService,
	}
}

// TODO: SET up CORS policy properly
// TODO: SET UP XSS headers to make smaller XSS attacks' vector

func (h *Handler) SetUpRoutesAndAccessPolicy(router chi.Router) {
	api := router.Route("/api", func(r chi.Router) {
		r.Use(
			middleware.SetHeader("Content-Type", "application/json"),
			rest.IsJSONMiddleware,
			httprate.Limit(
				7,
				time.Second,
				httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
					rest.WriteErrorResponse(
						r.Context(), common.NewTooManyRequestsError("Too many requests"), w, nil)
				}),
			),
		)
	})

	// TODO: handlers that are responsible for resending email should be documented appropriately in
	// opeanapi spec

	api.Get("/countries", h.getCountries)
	api.Post("/captcha", h.generateCaptcha)

	api.Route("/accounts", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(rest.AccessTokenMiddleware)
			// TODO: "CSRF protection middleware"

			r.Put("/", h.updateAccount)
			r.Post("/sending-verif-code/password-update", h.sendVerifCodeToUpdatePassword)
			r.Post("/session/logout", h.logout)
		})

		r.Put("/session/password", h.updatePassword)      // TODO: "CSRF protection middleware"
		r.Post("/session/access-token", h.getAccessToken) // TODO: "CSRF protection middleware"

		r.Post("/sign-up-pipe", h.startSignUpPipe)
		r.Post("/sending-verif-code/sign-up", h.resendVerifCodeForSignUp)

		r.Post("/sign-up", h.signUp)
		r.Post("/sign-in", h.signIn)
		r.Get("/sign-in/captcha-check", h.isSignInCaptcha)

		r.Post("/sending-verif-code/sessions-overflow", h.SendVerifCodeToCleanSessions)
		r.Post("/sessions-overflow-handling", h.HandleSessionsOverflow)

		r.Post("/password-reset-request", h.createPasswordResetRequest)
		r.Post("/password-reset", h.performPasswordReset)

		r.Get("/email", h.isAvailableEmail)
		r.Get("/nickname", h.isAvailableNickname)

		r.Get("/{nickname}/public", h.getAccount)
	})
}

func (h *Handler) getCountries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	countries, err := json.Marshal(enums.Countries)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, countries, http.StatusOK, w)
}

func (h *Handler) createPasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Print(r.Header)

	ctx := r.Context()

	var requestBody rest.PasswordResetRequest

	clientIP, err := rest.GetRealIP(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.PasswordResetRequestDTO{
		IP:                    clientIP,
		CaptchaID:             requestBody.CaptchaId,
		ProvidedCaptchaAnswer: requestBody.ProvidedCaptchaAnswer,
		Email:                 requestBody.Email,
	}

	pipeID, err := h.accountService.CreatePasswordResetRequest(ctx, dto)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	responseBody := rest.ReqForPasswordResetResponse{PipeId: pipeID}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) performPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.PasswordReset

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.PerformPasswordResetDTO{
		VerifCode:   requestBody.VerifCode,
		PipeID:      requestBody.PipeId,
		Email:       requestBody.Email,
		NewPassword: requestBody.NewPassword,
	}

	err := h.accountService.PerformPasswordReset(ctx, dto)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

func (h *Handler) generateCaptcha(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.GenerateCaptchaRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	captchaID, captcha, err := h.accountService.GenerateCaptcha(ctx, requestBody.CaptchaType)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	responseBody := rest.CaptchaResponse{
		CaptchaId: captchaID,
		Captcha:   captcha,
	}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) startSignUpPipe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.StartSignUpPipeRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.StartSignUpPipeDTO{
		CaptchaID:             requestBody.CaptchaId,
		ProvidedCaptchaAnswer: requestBody.ProvidedCaptchaAnswer,
		Email:                 requestBody.Email,
		Nickname:              requestBody.Nickname,
		Password:              requestBody.Password,
	}

	pipeID, err := h.accountService.StartSignUpPipe(ctx, dto)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	// TODO: add cookie that client has started pipeline. By doing this user will be able to continue sign up
	// pipeline even if they closed tab

	responseBody := rest.StartSignUpPipeResponse{
		PipeId: pipeID,
	}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) resendVerifCodeForSignUp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.VerifCodeForSignUpRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	if err := h.accountService.ResendVerifCodeForSignUp(ctx, requestBody.PipeId); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

func (h *Handler) signUp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.SignUpRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.SignUpDTO{
		ProvidedVerifCode: requestBody.VerifCode,
		PipeID:            requestBody.PipeId,
	}

	if err := h.accountService.SignUp(ctx, dto); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	// TODO: remove temporary cookie that indicates: sign up pipeline hasn't finished

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

// TODO: protect handler from free usage
func (h *Handler) isSignInCaptcha(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	email, err := rest.GetEmailFromURL(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	isCaptchaRequired, err := h.accountService.IsSignInCaptcha(ctx, email)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	responseBody := rest.IsCaptchaForSignInResponse{IsCaptcha: isCaptchaRequired}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

// TODO: test cases when:
// access token is hacked
// refresh token is hacked
// refresh token is hacked and user changes the password

const (
	refreshTokenCookieName = "refresh_token"
	refreshTokenCookiePath = "/rest/accounts/session"
)

func (h *Handler) signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.SignInRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	clientIP, err := rest.GetRealIP(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.SignInDTO{
		CaptchaID:             requestBody.CaptchaId,
		ProvidedCaptchaAnswer: requestBody.ProvidedCaptchaAnswer,
		Email:                 requestBody.Email,
		Password:              requestBody.Password,
		IP:                    clientIP,
	}

	resultDTO, err := h.accountService.SignIn(ctx, dto, auth.FileKeyReader)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	if resultDTO.SessionsOverflowPipeID != "" {
		err = common.NewClientSideError(
			"Sessions overflow for the account. The pipeline of cleaning sessions should be performed")

		meta := map[string]interface{}{"pipe_id": resultDTO.SessionsOverflowPipeID}

		rest.WriteErrorResponse(ctx, err, w, meta)
		return
	}

	responseBody := rest.SignInResponse{
		AccessToken: resultDTO.AccessToken,
	}

	cookie := http.Cookie{
		Name:  refreshTokenCookieName,
		Value: resultDTO.RefreshToken,

		Path: refreshTokenCookiePath,

		// TODO: enable secure cookie to ensure that the cookie is transferring only through https
		// Secure:   true,
		HttpOnly: true,

		// TODO: add expiration time for refresh token -> time.Now().Add(365 * 24 * time.Hour)
	}

	http.SetCookie(w, &cookie)

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) SendVerifCodeToCleanSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.SendCodeToCleanSessionsRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	clientIP, err := rest.GetRealIP(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.SendVerifCodeToCleanSessionsDTO{
		IP:     clientIP,
		Email:  requestBody.Email,
		PipeID: requestBody.PipeId,
	}

	if err = h.accountService.SendVerifCodeToCleanSessions(ctx, dto); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

func (h *Handler) HandleSessionsOverflow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var requestBody rest.HandleSessionsOverflowRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	clientIP, err := rest.GetRealIP(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.HandleSessionsOverflowDTO{
		Email:     requestBody.Email,
		VerifCode: requestBody.VerifCode,
		IP:        clientIP,
		PipeID:    requestBody.PipeId,
	}

	accessToken, refreshToken, err := h.accountService.HandleSessionsOverflow(ctx, dto, auth.FileKeyReader)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	responseBody := rest.HandleSessionsOverflowResponse{
		AccessToken: accessToken,
	}

	cookie := http.Cookie{
		Name:  refreshTokenCookieName,
		Value: refreshToken,

		Path: refreshTokenCookiePath,

		// TODO: enable secure cookie to ensure that the cookie is transferring only through https
		// Secure:   true,
		HttpOnly: true,

		// TODO: add expiration time for refresh token -> time.Now().Add(365 * 24 * time.Hour)
	}

	http.SetCookie(w, &cookie)

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie(refreshTokenCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			err = common.NewClientSideError("error occurred when getting refresh token")
		}

		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	refreshToken := cookie.Value

	if err := h.accountService.Logout(ctx, refreshToken, auth.FileKeyReader); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	refreshTokenCookie := http.Cookie{
		Name:  refreshTokenCookieName,
		Value: "",

		Path: refreshTokenCookiePath,

		// TODO: enable secure cookie to ensure that the cookie is transferring only through https
		// Secure:   true,
		HttpOnly: true,
		Expires:  time.Time{},
	}

	http.SetCookie(w, &refreshTokenCookie)

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

func (h *Handler) getAccessToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie(refreshTokenCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			err = common.NewClientSideError("error occurred when getting refresh token")
		}

		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	refreshToken := cookie.Value

	accessToken, err := h.accountService.GetAccessToken(ctx, refreshToken, auth.FileKeyReader)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	responseBody := rest.AccessTokenResponse{
		AccessToken: accessToken,
	}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

func (h *Handler) updateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := rest.GetAccountIDFromJWT(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	var requestBody rest.UpdateAccountRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	dto := &account.UpdateAccountDTO{
		ID:             accountID,
		BirthDate:      requestBody.BirthDate.Time,
		CurrentCountry: requestBody.CurrentCountry,
		FirstName:      requestBody.FirstName,
		LastName:       requestBody.LastName,
	}

	err = h.accountService.UpdateAccount(ctx, dto)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, nil, http.StatusNoContent, w)
}

func (h *Handler) sendVerifCodeToUpdatePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := rest.GetAccountIDFromJWT(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	if err := h.accountService.SendVerifCodeForPasswordUpdate(ctx, accountID); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, nil, http.StatusNoContent, w)
}

func (h *Handler) updatePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie(refreshTokenCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			err = common.NewClientSideError("error occurred when getting refresh token")
		}

		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	refreshToken := cookie.Value

	var requestBody rest.UpdatePasswordRequest

	if err := rest.BindAndValidate(r, &requestBody); err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	feelLikeGetHacked, err := strconv.ParseBool(requestBody.FeelLikeGetHacked)
	if err != nil {
		err = common.NewClientSideError("invalid value provided for 'feel like get hacked'")
		rest.WriteErrorResponse(ctx, err, w, nil)

		return
	}

	dto := &account.UpdatePasswordDTO{
		RefreshToken:      refreshToken,
		ProvidedVerifCode: requestBody.VerifCode,
		NewPassword:       requestBody.NewPassword,
		FeelLikeGetHacked: feelLikeGetHacked,
	}

	newRefreshToken, err := h.accountService.UpdatePassword(ctx, dto, auth.FileKeyReader)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	refreshTokenCookie := http.Cookie{
		Name:  refreshTokenCookieName,
		Value: newRefreshToken,

		Path: refreshTokenCookiePath,

		// TODO: enable secure cookie to ensure that the cookie is transferring only through https
		// Secure:   true,
		HttpOnly: true,

		// TODO: add expiration time for refresh token -> time.Now().Add(365 * 24 * time.Hour)
	}

	http.SetCookie(w, &refreshTokenCookie)

	rest.WriteResponse(ctx, []byte{}, http.StatusNoContent, w)
}

func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nickname, err := rest.GetNicknameFromPath(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	entity, err := h.accountService.GetAccount(ctx, nickname)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	birthDate := entity.GetBirthDate()

	responseBody := rest.AccountResponse{
		BirthDate:      types.Date{Time: birthDate},
		CurrentCountry: entity.GetCurrentCountry(),
		Email:          entity.GetEmail(),
		FirstName:      entity.GetFirstName(),
		LastName:       entity.GetLastName(),
		Nickname:       entity.GetNickname(),
	}

	response, err := json.Marshal(responseBody)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

// TODO: protect handler from free usage
func (h *Handler) isAvailableEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	email, err := rest.GetEmailFromURL(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	available, err := h.accountService.IsAvailableEmail(ctx, email)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	response, err := json.Marshal(map[string]bool{"available": available})
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}

// TODO: protect handler from free usage
func (h *Handler) isAvailableNickname(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nickname, err := rest.GetNicknameFromURL(r)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	available, err := h.accountService.IsAvailableNickname(ctx, nickname)
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	response, err := json.Marshal(map[string]bool{"available": available})
	if err != nil {
		rest.WriteErrorResponse(ctx, err, w, nil)
		return
	}

	rest.WriteResponse(ctx, response, http.StatusOK, w)
}
