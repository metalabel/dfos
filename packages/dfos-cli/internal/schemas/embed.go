package schemas

import _ "embed"

//go:embed post.v1.json
var PostV1 []byte

//go:embed profile.v1.json
var ProfileV1 []byte

//go:embed manifest.v1.json
var ManifestV1 []byte
