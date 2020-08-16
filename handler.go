package auth

import (
	"context"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/codec"
	"github.com/neuronlabs/neuron/controller"
	"github.com/neuronlabs/neuron/errors"
	"github.com/neuronlabs/neuron/mapping"
	"github.com/neuronlabs/neuron/query/filter"
	"github.com/neuronlabs/neuron/server"
)

// CheckUsernameHandler is an interface that allows to check the username in a custom way.
type CheckUsernameHandler interface {
	HandleCheckUsername(ctx context.Context, params server.Params, account auth.Account, meta codec.Meta) error
}

// AccountInsertHandler is an interface that allows to handle account insertion in a custom way.
type AccountInsertHandler interface {
	HandleInsertAccount(ctx context.Context, params server.Params, account auth.Account, password *auth.Password, meta codec.Meta) error
}

type AccountGetterHandler interface {
	HandleGetAccount(ctx context.Context, params server.Params, account auth.Account) error
}

// BeforeAccountInserter is an interface used for handling hook before insertion of account.
type BeforeAccountInserter interface {
	BeforeInsertAccount(ctx context.Context, params server.Params, account auth.Account, password *auth.Password, meta codec.Meta) error
}

// AfterAccountInserter is an interface used for handling hook after insertion of account.
// Within this hook, developer could set some functions that send emails, sets some additional models etc.
type AfterAccountInserter interface {
	AfterInsertAccount(ctx context.Context, params server.Params, account auth.Account, password *auth.Password, meta codec.Meta) error
}

// InsertedAccountMarshaler.
type InsertedAccountMarshaler interface {
	MarshalInsertedAccount(ctx context.Context, params server.Params, account auth.Account, meta codec.Meta) (*codec.Payload, error)
}

type DefaultHandler struct {
	Account       auth.Account
	Model         *mapping.ModelStruct
	UsernameField *mapping.StructField
	PasswordField *mapping.StructField
}

// HandleCheckUsername implements CheckUsernameHandler interface.
func (d *DefaultHandler) HandleCheckUsername(ctx context.Context, params server.Params, account auth.Account, meta codec.Meta) error {
	cnt, err := params.DB.QueryCtx(ctx, d.Model).
		Filter(filter.New(d.UsernameField, filter.OpEqual, account.GetUsername())).
		Count()
	if err != nil {
		return err
	}
	if cnt > 0 {
		return errors.WrapDet(auth.ErrAccountAlreadyExists, "account already exists").
			WithDetail("An account with provided username already exists")
	}
	return nil
}

// HandleInsertAccount implements InsertAccountHandler interface.
func (d *DefaultHandler) HandleInsertAccount(ctx context.Context, params server.Params, account auth.Account, password *auth.Password, meta codec.Meta) error {
	return params.DB.Insert(ctx, d.Model, account)
}

// Initialize implements core.Initializer.
func (d *DefaultHandler) Initialize(c *controller.Controller) error {
	// Find the username field.
	var err error
	d.Model, err = c.ModelStruct(d.Account)
	if err != nil {
		return err
	}
	var ok bool
	d.UsernameField, ok = d.Model.FieldByName(d.Account.UsernameField())
	if !ok {
		return errors.Wrapf(auth.ErrInitialization, "provided invalid account model - no username field: '%s' found in the model: %s", d.Account.UsernameField(), d.Model)
	}
	d.PasswordField, ok = d.Model.FieldByName(d.Account.PasswordHashField())
	if !ok {
		return errors.Wrapf(auth.ErrInitialization, "provided invalid account model - no password hash field: '%s' found in the model: %s", d.Account.PasswordHashField(), d.Model)
	}
	return nil
}
