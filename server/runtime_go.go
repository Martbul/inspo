package server

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"

	"plugin"

	"github.com/martbul/inspo-common/runtime"
	"go.uber.org/zap"
)

func CheckRuntimeProviderGo(logger *zap.Logger, rootPath string, paths []string) error {
	for _, path := range paths {
		// Skip everything except shared object files.
		if strings.ToLower(filepath.Ext(path)) != ".so" {
			continue
		}

		// Open the plugin, and look up the required initialisation function.
		// The function isn't used here, all we need is a type/signature check.
		_, _, _, err := openGoModule(logger, rootPath, path)
		if err != nil {
			// Errors are already logged in the function above.
			return err
		}
	}

	return nil
}
func openGoModule(logger *zap.Logger, rootPath, path string) (string, string, func(context.Context, runtime.Logger, *sql.DB, runtime.NakamaModule, runtime.Initializer) error, error) {
	relPath, _ := filepath.Rel(rootPath, path)
	name := strings.TrimSuffix(relPath, filepath.Ext(relPath))

	// Open the plugin.
	p, err := plugin.Open(path)
	if err != nil {
		logger.Error("Could not open Go module", zap.String("path", path), zap.Error(err))
		return "", "", nil, err
	}

	// Look up the required initialisation function.
	f, err := p.Lookup("InitModule")
	if err != nil {
		logger.Fatal("Error looking up InitModule function in Go module", zap.String("name", name))
		return "", "", nil, err
	}

	// Ensure the function has the correct signature.
	fn, ok := f.(func(context.Context, runtime.Logger, *sql.DB, runtime.NakamaModule, runtime.Initializer) error)
	if !ok {
		logger.Fatal("Error reading InitModule function in Go module", zap.String("name", name))
		return "", "", nil, errors.New("error reading InitModule function in Go module")
	}

	return relPath, name, fn, nil
}
