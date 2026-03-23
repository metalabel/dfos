module github.com/metalabel/dfos/packages/dfos-cli

go 1.26

require (
	github.com/metalabel/dfos/packages/dfos-protocol-go v0.0.0
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/spf13/cobra v1.10.2
	github.com/zalando/go-keyring v0.2.7
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.27.0 // indirect
)

replace github.com/metalabel/dfos/packages/dfos-protocol-go => ../dfos-protocol-go
