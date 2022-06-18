package assets

import "embed"

// Assets represents the embedded files.
//go:embed *
var assets embed.FS

func GetResources() embed.FS {
	return assets
}
