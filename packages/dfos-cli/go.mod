module github.com/metalabel/dfos/packages/dfos-cli

go 1.26

require (
	github.com/mattn/go-isatty v0.0.22
	github.com/metalabel/dfos/packages/dfos-protocol-go v0.0.0
	github.com/metalabel/dfos/packages/dfos-web-relay-go v0.0.0
	github.com/pb33f/libopenapi v0.38.7
	github.com/pelletier/go-toml/v2 v2.3.1
	github.com/spf13/cobra v1.10.2
	github.com/zalando/go-keyring v0.2.8
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/sys v0.46.0
	golang.org/x/term v0.44.0
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pb33f/jsonpath v0.8.2 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sync v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.73.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.52.0 // indirect
)

replace (
	github.com/metalabel/dfos/packages/dfos-protocol-go => ../dfos-protocol-go
	github.com/metalabel/dfos/packages/dfos-web-relay-go => ../dfos-web-relay-go
)
