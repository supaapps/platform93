package migrations

import "embed"

// FS is the immutable migration set embedded in every Platform93 binary.
//
//go:embed *.sql
var FS embed.FS
