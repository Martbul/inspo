package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

var (
	ErrRuntimeRPCNotFound = errors.New("RPC function not found")
)

const API_PREFIX = "/inspo.api.Inspo/"
const RTAPI_PREFIX = "*rtapi.Envelope_"

var API_PREFIX_LOWERCASE = strings.ToLower(API_PREFIX)
var RTAPI_PREFIX_LOWERCASE = strings.ToLower(RTAPI_PREFIX)

func GetRuntimePaths(logger *zap.Logger, rootPath string) ([]string, error) {
	if err := os.MkdirAll(rootPath, os.ModePerm); err != nil {
		return nil, err
	}

	paths := make([]string, 0, 5)
	if err := filepath.Walk(rootPath, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error listing runtime path", zap.String("path", path), zap.Error(err))
			return err
		}

		// Ignore directories.
		if !f.IsDir() {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		logger.Error("Failed to list runtime path", zap.Error(err))
		return nil, err
	}

	return paths, nil
}

func CheckRuntime(logger *zap.Logger, config Config, version string) error {
	// Get all paths inside the configured runtime.
	paths, err := GetRuntimePaths(logger, config.GetRuntime().Path)
	if err != nil {
		return err
	}

	// Check any Go runtime modules.
	err = CheckRuntimeProviderGo(logger, config.GetRuntime().Path, paths)
	if err != nil {
		return err
	}

	// Check any Lua runtime modules.
	err = CheckRuntimeProviderLua(logger, config, version, paths)
	if err != nil {
		return err
	}

	// Check any JavaScript runtime modules.
	err = CheckRuntimeProviderJavascript(logger, config, version)
	if err != nil {
		return err
	}

	return nil
}
