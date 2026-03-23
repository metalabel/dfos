module github.com/metalabel/dfos/packages/dfos-web-relay/conformance

go 1.26

require github.com/metalabel/dfos/packages/dfos-protocol-go v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/metalabel/dfos/packages/dfos-protocol-go => ../../dfos-protocol-go
