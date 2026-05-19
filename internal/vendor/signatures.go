package vendor

import _ "embed"

//go:embed signatures/vendors.json
var signaturesJSON []byte
