package github

import "github.com/timreynolds/custodian/internal/github/write"

// Thin re-exports from internal/github/write so callers importing internal/github
// can access write types while internal/git/publish and cmd/custodian-publisher
// import internal/github/write directly without pulling in internal/git/checkout.
type (
	WriteConfig          = write.WriteConfig
	WriteClient          = write.WriteClient
	WriteInterface       = write.Client
	RepositoryAccess     = write.RepositoryAccess
	PullRequestParams    = write.PullRequestParams
	PullRequestResult    = write.PullRequestResult
	LocalBareWriteClient = write.LocalBareClient
	LocalBareWriteOption = write.LocalBareOption
)

// NewWriteClient constructs a write-scoped GitHub App client.
var NewWriteClient = write.NewWriteClient

// NewLocalBareWriteClient constructs a checkout-free local bare write/PR client.
var NewLocalBareWriteClient = write.NewLocalBareClient
