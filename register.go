package auth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	codecJson "github.com/neuronlabs/neuron-extensions/codec/json"
	"github.com/neuronlabs/neuron-extensions/server/http/httputil"
	"github.com/neuronlabs/neuron-extensions/server/http/log"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/codec"
	"github.com/neuronlabs/neuron/database"
	"github.com/neuronlabs/neuron/errors"
	"github.com/neuronlabs/neuron/mapping"
	"github.com/neuronlabs/neuron/server"
)

// AccountCreateInput is an input for the account creation.
type AccountCreateInput struct {
	Meta                 codec.Meta `json:"meta"`
	Username             string     `json:"username"`
	Password             string     `json:"password"`
	PasswordConfirmation string     `json:"password_confirmation"`
}

func (a *API) handleCreateAccount(rw http.ResponseWriter, req *http.Request) {
	input, err := a.decodeAccountCreateInput(req)
	if err != nil {
		a.marshalErrors(rw, 0, err)
		return
	}

	// Score and analyze the password.
	password := auth.NewPassword(input.Password, a.Options.PasswordScorer)

	// Validate the password.
	if err := a.Options.PasswordValidator(password); err != nil {
		httpError := httputil.ErrInvalidJSONFieldValue()
		httpError.Detail = "Provided invalid password."
		if detailer, ok := err.(*errors.DetailedError); ok {
			httpError.Detail = detailer.Details
		}
		a.marshalErrors(rw, 400, httpError)
		return
	}

	// Validate the username.
	if err := a.Options.UsernameValidator(input.Username); err != nil {
		httpError := httputil.ErrInvalidJSONFieldValue()
		httpError.Detail = "Provided invalid username."
		if detailer, ok := err.(*errors.DetailedError); ok {
			httpError.Detail = detailer.Details
		}
		a.marshalErrors(rw, 400, httpError)
		return
	}

	ctx := req.Context()

	// Create new model and sets it's username and password.
	model := mapping.NewModel(a.model).(auth.Account)
	model.SetUsername(input.Username)

	// Execute create account
	var payload *codec.Payload
	err = database.RunInTransaction(ctx, a.serverOptions.DB, nil, func(db database.DB) error {
		params := server.Params{
			Ctx:           ctx,
			Authorizer:    a.serverOptions.Authorizer,
			Authenticator: a.Authenticator,
			Tokener:       a.Tokener,
			DB:            db,
		}
		err := a.createAccount(ctx, params, model, password, input.Meta)
		if err != nil {
			return err
		}
		customMarshaler, ok := a.Options.AccountHandler.(InsertedAccountMarshaler)
		if !ok {
			return nil
		}
		payload, err = customMarshaler.MarshalInsertedAccount(ctx, params, model, input.Meta)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		a.marshalErrors(rw, 0, err)
		return
	}
	if payload == nil {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	// Marshal given payload into json codec.
	payload.ModelStruct = a.model
	payload.MarshalSingularFormat = true

	cdc := jsonCodec.GetCodec(a.serverOptions.Controller)

	if err := cdc.MarshalPayload(rw, payload); err != nil {
		log.Errorf("Marshaling account payload failed: %v", err)
	}
}

func (a *API) createAccount(ctx context.Context, params server.Params, account auth.Account, password *auth.Password, meta codec.Meta) error {
	// Check if the username exists.
	checkHandler, ok := a.Options.AccountHandler.(CheckUsernameHandler)
	if !ok {
		checkHandler = a.defaultHandler
	}
	if err := checkHandler.HandleCheckUsername(ctx, params, account, meta); err != nil {
		return err
	}

	// Check if before insert hook exists.
	if beforeInserter, ok := a.Options.AccountHandler.(BeforeAccountInserter); ok {
		if err := beforeInserter.BeforeInsertAccount(ctx, params, account, password, meta); err != nil {
			return err
		}
	}

	// Execute inserter hook.
	inserter, ok := a.Options.AccountHandler.(AccountInsertHandler)
	if !ok {
		inserter = a.defaultHandler
	}
	if err := inserter.HandleInsertAccount(ctx, params, account, password, meta); err != nil {
		return err
	}

	// Handle after insert hook.
	if afterInserter, ok := a.Options.AccountHandler.(AfterAccountInserter); ok {
		if err := afterInserter.AfterInsertAccount(ctx, params, account, password, meta); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) decodeAccountCreateInput(req *http.Request) (*AccountCreateInput, error) {
	input := &AccountCreateInput{}
	switch req.Header.Get("Content-Type") {
	case "application/json":
		d := json.NewDecoder(req.Body)
		if a.Options.StrictUnmarshal {
			d.DisallowUnknownFields()
		}
		if err := d.Decode(input); err != nil {
			return nil, errors.WrapDetf(codec.ErrUnmarshalDocument, "decode failed: %v", err).
				WithDetail("Provided invalid input document.")
		}
	case "application/x-www-form-urlencoded":
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, errors.WrapDet(codec.ErrUnmarshalDocument, "reading failed")
		}
		q, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, errors.WrapDet(codec.ErrUnmarshalDocument, "parsing form failed").WithDetail("Parsing form failed.")
		}

		input.Username = q.Get("username")
		input.Password = q.Get("password")
		input.PasswordConfirmation = q.Get("password_confirmation")
	default:
		err := req.ParseForm()
		if err != nil {
			return nil, errors.WrapDet(codec.ErrUnmarshalDocument, "provided invalid post form").WithDetail("invalid post form")
		}
		q := req.PostForm
		input.Username = q.Get("username")
		input.Password = q.Get("password")
		input.PasswordConfirmation = q.Get("password_confirmation")
	}
	return input, nil
}

// var emailRegexp = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

//
// func (a *API) validateEmail(acc *account.Account) *codec.Error {
// 	if acc.Email == "" {
// 		httpError := httputil.ErrInvalidJSONFieldValue()
// 		httpError.Detail = "Provided empty email."
// 		return httpError
// 	}
// 	if emailRegexp.MatchString(acc.Email) {
// 		httpError := httputil.ErrInvalidJSONFieldValue()
// 		httpError.Detail = "Username is of invalid format."
// 		return httpError
// 	}
// }

// func (a *API) validatePassword(acc *account.Account) *codec.Error {
// 	var httpError *codec.Error
// 	if acc.Password == "" && a.AuthenticatorOptions.MinPasswordLength != 0 {
// 		httpError = httputil.ErrInvalidJSONFieldValue()
// 		httpError.Detail = "Provided empty password."
// 		return httpError
// 	}
// 	if len(acc.Password) < a.AuthenticatorOptions.MinPasswordLength {
// 		httpError = httputil.ErrInvalidJSONFieldValue()
// 		httpError.Detail = fmt.Sprintf("Password needs to be at least %d long.", a.AuthenticatorOptions.MinPasswordLength)
// 	}
// 	if a.AuthenticatorOptions.PasswordRequireCapital || a.AuthenticatorOptions.PasswordRequireNumber || a.AuthenticatorOptions.PasswordRequireSpecial {
// 		var hasUpper, hasDigit, hasSpecial bool
// 		const specials = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
// 		for _, rn := range acc.Password {
// 			switch {
// 			case unicode.IsUpper(rn):
// 				hasUpper = true
// 			case unicode.IsDigit(rn):
// 				hasDigit = true
// 			}
// 		}
// 		hasSpecial = strings.ContainsAny(acc.Password, specials)
// 		if a.AuthenticatorOptions.PasswordRequireCapital && !hasUpper {
// 			if httpError == nil {
// 				httpError = httputil.ErrInvalidJSONFieldValue()
// 			}
// 			if httpError.Detail != "" {
// 				httpError.Detail += " "
// 			}
// 			httpError.Detail += "Password needs to have at least one uppercase letter."
// 		}
// 		if a.AuthenticatorOptions.PasswordRequireSpecial && !hasSpecial {
// 			if httpError == nil {
// 				httpError = httputil.ErrInvalidJSONFieldValue()
// 			}
// 			if httpError.Detail != "" {
// 				httpError.Detail += " "
// 			}
// 			httpError.Detail += fmt.Sprintf("Password needs to have at least one special symbol - %s.", specials)
// 		}
// 		if a.AuthenticatorOptions.PasswordRequireNumber && !hasDigit {
// 			if httpError == nil {
// 				httpError = httputil.ErrInvalidJSONFieldValue()
// 			}
// 			if httpError.Detail != "" {
// 				httpError.Detail += " "
// 			}
// 			httpError.Detail += "Password needs to have at least one digit."
// 		}
// 	}
// 	return httpError
// }
