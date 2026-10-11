// Package templates embeds the server-rendered HTML pages (login, error).
package templates

import (
	"embed"
	"html/template"
)

//go:embed *.html
var files embed.FS

// Login renders the login form.
var Login = template.Must(template.ParseFS(files, "login.html"))

// Error renders a generic error page used when we cannot safely redirect to a
// client (bad client_id, bad redirect_uri, etc.).
var Error = template.Must(template.ParseFS(files, "error.html"))

// LoginData is the data model for Login.
type LoginData struct {
	CSRFToken  string
	ReturnTo   string
	Identifier string
	Error      string
}

// ErrorData is the data model for Error.
type ErrorData struct {
	Code        string
	Description string
}
