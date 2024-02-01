package common

import "fmt"

type ClientSideError struct {
	Title string `json:"title"`
}

func NewClientSideError(title string) error {
	return &ClientSideError{
		title,
	}
}

func (cse *ClientSideError) Error() string {
	return cse.Title
}

func (cse *ClientSideError) Is(tgt error) bool {
	//nolint:errorlint
	_, ok := tgt.(*ClientSideError)
	return ok
}

type ValidationError struct {
	Title  string   `json:"title"`
	Errors []string `json:"errors"`
}

func NewValidationError(title string, errors []string) error {
	return &ValidationError{
		Title:  title,
		Errors: errors,
	}
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("%s, Errors: %v", ve.Title, ve.Errors)
}

type ServerSideError struct {
	Title string `json:"title"`
}

func NewServerSideError(title string) error {
	return &ServerSideError{
		Title: title,
	}
}

func (sse *ServerSideError) Error() string {
	return sse.Title
}

type TooManyRequestsError struct {
	Title string `json:"title"`
}

func NewTooManyRequestsError(title string) error {
	return &TooManyRequestsError{
		Title: title,
	}
}

func (tmre *TooManyRequestsError) Error() string {
	return tmre.Title
}
