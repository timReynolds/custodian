package api

import "embed"

// SpecFS embeds the Custodian OpenAPI 3.1 specification and modular schema files
// so contract validation and HTTP request/response validation work completely offline.
//
//go:embed openapi.yaml schemas/*.yaml
var SpecFS embed.FS
