package auth

import (
	"time"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/server"
)

// AuthenticatorOptions is the structure that contains auth API  settings.
type Options struct {
	AccountModel            auth.Account
	AccountHandler          interface{}
	PathPrefix              string
	Middlewares             []server.Middleware
	StrictUnmarshal         bool
	PasswordValidator       auth.PasswordValidator
	PasswordScorer          auth.PasswordScorer
	UsernameValidator       auth.UsernameValidator
	TokenExpiration         time.Duration
	RememberTokenExpiration time.Duration
	RefreshTokenExpiration  time.Duration
}

func defaultOptions() *Options {
	return &Options{
		PasswordScorer:          auth.DefaultPasswordScorer,
		PasswordValidator:       auth.DefaultPasswordValidator,
		UsernameValidator:       auth.DefaultUsernameValidator,
		TokenExpiration:         time.Hour * 24,
		RememberTokenExpiration: time.Hour * 24 * 7,
		RefreshTokenExpiration:  time.Hour * 24 * 30,
	}
}

type Option func(o *Options)

// WithAccountModel is an option that sets the account model within options.
func WithAccountModel(account auth.Account) Option {
	return func(o *Options) {
		o.AccountModel = account
	}
}

// WithAccountHandler is an option that sets the account handler.
func WithAccountHandler(handler interface{}) Option {
	return func(o *Options) {
		o.AccountHandler = handler
	}
}

// WithPathPrefix is an option that sets path prefix for the API.
func WithPathPrefix(pathPrefix string) Option {
	return func(o *Options) {
		o.PathPrefix = pathPrefix
	}
}

// WithStrictUnmarshal is an option that sets the 'StrictUnmarshal' setting.
func WithStrictUnmarshal(setting bool) Option {
	return func(o *Options) {
		o.StrictUnmarshal = setting
	}
}

// WithPasswordScorer sets the password scorer for the auth options.
func WithPasswordScorer(scorer auth.PasswordScorer) Option {
	return func(o *Options) {
		o.PasswordScorer = scorer
	}
}

// WithUsernameValidator sets the username validator function.
func WithUsernameValidator(validator auth.UsernameValidator) Option {
	return func(o *Options) {
		o.UsernameValidator = validator
	}
}

// WithPasswordValidator sets the password validator function.
func WithPasswordValidator(validator auth.PasswordValidator) Option {
	return func(o *Options) {
		o.PasswordValidator = validator
	}
}

// WithTokenExpiration sets the 'TokenExpiration' option for the auth service.
func WithTokenExpiration(d time.Duration) Option {
	return func(o *Options) {
		o.TokenExpiration = d
	}
}

// WithRememberMeTokenExpiration sets the 'RememberTokenExpiration' option for the auth service.
func WithRememberMeTokenExpiration(d time.Duration) Option {
	return func(o *Options) {
		o.RememberTokenExpiration = d
	}
}

// WithRefreshTokenExpiration sets the 'RefreshTokenExpiration' option for the auth service.
func WithRefreshTokenExpiration(d time.Duration) Option {
	return func(o *Options) {
		o.RefreshTokenExpiration = d
	}
}

// WithMiddlewares adds middlewares for all auth.API endpoints.
func WithMiddlewares(middlewares ...server.Middleware) Option {
	return func(o *Options) {
		o.Middlewares = append(o.Middlewares, middlewares...)
	}
}
