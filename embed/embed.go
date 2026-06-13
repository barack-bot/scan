// Package embed provides a filesystem abstraction for templates and static assets.
package embed

import (
	"io/fs"
	"os"
	"path/filepath"
)

func locateRootDir() string {
	candidates := []string{"."}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, exeDir, filepath.Join(exeDir, ".."))
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "templates", "layouts", "base.html")); err == nil {
			return dir
		}
	}

	return "."
}

// GetTemplatesFS returns a filesystem containing templates.
func GetTemplatesFS() fs.FS {
	return os.DirFS(locateRootDir())
}

// GetStaticFS returns a filesystem containing static assets.
func GetStaticFS() fs.FS {
	return os.DirFS(locateRootDir())
}
