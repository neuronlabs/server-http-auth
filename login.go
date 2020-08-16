package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/neuronlabs/neuron-extensions/server/http/httputil"
	"github.com/neuronlabs/neuron-extensions/server/http/log"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/codec"
	"github.com/neuronlabs/neuron/errors"
	"github.com/neuronlabs/neuron/mapping"
	"github.com/neuronlabs/neuron/query"
	"github.com/neuronlabs/neuron/server"
)

// LoginInput is the input login structure.
type LoginInput struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	RememberToken bool   `json:"remember_token"`
}

// LoginOutput is the successful login output structure.
type LoginOutput struct {
	Meta         codec.Meta `json:"meta,omitempty"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	TokenType    string     `json:"token_type,omitempty"`
	ExpiresIn    int64      `json:"expires_in,omitempty"`
}

func (a *API) handleLoginEndpoint(rw http.ResponseWriter, req *http.Request) {
	input := &LoginInput{}

	username, password, hasBasicAuth := req.BasicAuth()
	switch req.Header.Get("Content-Type") {
	case "application/json":
		d := json.NewDecoder(req.Body)
		if a.Options.StrictUnmarshal {
			d.DisallowUnknownFields()
		}
		if err := d.Decode(input); err != nil {
			a.marshalErrors(rw, 400, errors.WrapDetf(codec.ErrUnmarshalDocument, "decode failed: %v", err).
				WithDetail("Provided invalid input document."))
			return
		}
	case "application/x-www-form-urlencoded":
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			a.marshalErrors(rw, 400, errors.WrapDet(codec.ErrUnmarshalDocument, "reading failed"))
			return
		}
		q, err := url.ParseQuery(string(body))
		if err != nil {
			a.marshalErrors(rw, 400, errors.WrapDet(codec.ErrUnmarshalDocument, "parsing form failed").WithDetail("Parsing form failed."))
			return
		}

		input.Username = q.Get("username")
		input.Password = q.Get("password")
		input.RememberToken = q.Get("remember_token") == "true"
	default:
		err := req.ParseForm()
		if err != nil && !hasBasicAuth {
			a.marshalErrors(rw, 400, errors.WrapDet(codec.ErrUnmarshalDocument, "provided invalid post form").WithDetail("invalid post form"))
			return
		}
		q := req.PostForm
		input.Username = q.Get("username")
		input.Password = q.Get("password")
		input.RememberToken = q.Get("remember_token") == "true"
	}

	if hasBasicAuth {
		input.Username = username
		input.Password = password
	}

	// Validate provided username.
	if a.Options.UsernameValidator != nil {
		if err := a.Options.UsernameValidator(input.Username); err != nil {
			httpError := httputil.ErrInvalidJSONFieldValue()
			httpError.Detail = "Provided invalid username."
			if detailer, ok := err.(*errors.DetailedError); ok {
				httpError.Detail = detailer.Details
			}
			a.marshalErrors(rw, 400, httpError)
			return
		}
	}

	// Validate password.
	if a.Options.PasswordValidator != nil {
		neuronPassword := auth.NewPassword(input.Password, a.Options.PasswordScorer)
		if err := a.Options.PasswordValidator(neuronPassword); err != nil {
			httpError := httputil.ErrInvalidJSONFieldValue()
			httpError.Detail = "Provided invalid neuronPassword."
			if detailer, ok := err.(*errors.DetailedError); ok {
				httpError.Detail = detailer.Details
			}
			a.marshalErrors(rw, 400, httpError)
			return
		}
	}

	model := mapping.NewModel(a.model).(auth.Account)
	model.SetUsername(input.Username)

	// GetUser
	ctx := req.Context()
	params := server.Params{
		Ctx:           ctx,
		Authorizer:    a.serverOptions.Authorizer,
		Authenticator: a.Authenticator,
		Tokener:       a.Tokener,
		DB:            a.serverOptions.DB,
	}

	// Get the account model.
	// TODO: replace with a hook.
	if err := params.DB.QueryCtx(ctx, a.model, model).Refresh(); err != nil {
		if errors.Is(err, query.ErrQueryNoResult) {
			httpError := httputil.ErrInvalidAuthenticationInfo()
			httpError.Detail = "username or neuronPassword is not valid"
			a.marshalErrors(rw, 0, httpError)
			return
		}
		a.marshalErrors(rw, 0, err)
		return
	}

	// Check Password
	if err := a.Authenticator.ComparePassword(model, input.Password); err != nil {
		// TODO: create a hook here.
		httpError := httputil.ErrInvalidAuthenticationInfo()
		httpError.Detail = "username or neuronPassword is not valid"
		a.marshalErrors(rw, 0, httpError)
		return
	}

	expiration := a.Options.TokenExpiration
	if input.RememberToken {
		expiration = a.Options.RememberTokenExpiration
	}

	// Create Token
	token, err := a.Tokener.Token(model,
		auth.TokenExpirationTime(expiration),
		auth.TokenRefreshExpirationTime(a.Options.RefreshTokenExpiration),
	)
	if err != nil {
		a.marshalErrors(rw, 0, err)
		return
	}

	output := &LoginOutput{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int64(token.ExpiresIn),
	}

	buffer := &bytes.Buffer{}
	if err = json.NewEncoder(buffer).Encode(output); err != nil {
		a.marshalErrors(rw, 500, httputil.ErrInternalError())
		return
	}
	rw.WriteHeader(http.StatusCreated)
	if _, err = buffer.WriteTo(rw); err != nil {
		log.Errorf("Writing to response writer failed: %v", err)
	}
}
