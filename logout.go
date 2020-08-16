package auth

import (
	"net/http"
	"strings"

	"github.com/neuronlabs/neuron-extensions/server/http/httputil"

	"github.com/neuronlabs/neuron/auth"
	"github.com/neuronlabs/neuron/errors"
)

func (a *API) logout(rw http.ResponseWriter, req *http.Request) {
	token, err := a.getBearerToken(rw, req)
	if err != nil {
		a.marshalErrors(rw, 401, err)
		return
	}
	a.Tokener.InspectToken()

}

func (a *API) getBearerToken(rw http.ResponseWriter, req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", errors.WrapDetf(auth.ErrAuthorizationHeader, "no bearer found").WithDetail("Authorization Header doesn't contain 'Bearer' token")

	}
	token := strings.TrimPrefix(header, "Bearer ")
	return token, nil
}
