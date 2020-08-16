package auth

import (
	"net/http"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/errors"
)

func (a *API) refreshToken(rw http.ResponseWriter, req *http.Request) {
	token, err := a.getBearerToken(rw, req)
	if err != nil {
		a.marshalErrors(rw, 401, err)
		return
	}
	ctx := req.Context()
	claims, err := a.Tokener.InspectToken(ctx, token)
	if err != nil {
		a.marshalErrors(rw, 0, err)
		return
	}

	// Check if the claims are valid.
	if !claims.Valid() {
		a.marshalErrors(rw, 401, errors.Wrap(auth.ErrTokenExpired))
		return
	}

	switch claims.(type) {
	case auth.RefreshClaims:
	case auth.AccessClaims:
	}
}
