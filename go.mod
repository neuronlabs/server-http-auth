module github.com/neuronlabs/neuron-extensions/server/http/api/auth

go 1.13

replace (
	github.com/neuronlabs/neuron => ./../../../../../neuron
)

require (
	github.com/julienschmidt/httprouter v1.3.0
	github.com/neuronlabs/neuron latest
	github.com/neuronlabs/neuron-extensions/codec/json v0.0.0-20200809202509-265289d6988d
	github.com/neuronlabs/neuron-extensions/server/http v0.0.0-20200809201148-e794bdb0ac7f
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de // indirect
)
