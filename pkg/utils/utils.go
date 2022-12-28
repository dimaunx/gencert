package utils

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// CreateDir creates a local directory for certificates.
func CreateDir(path string) error {
	currDir, err := os.Getwd()
	if err != nil {
		return err
	}

	fullPath := filepath.Join(currDir, path)
	if _, err = os.Stat(fullPath); os.IsNotExist(err) {
		if err = os.MkdirAll(fullPath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}
	return errors.Errorf("directory: %s already exists", fullPath)
}
