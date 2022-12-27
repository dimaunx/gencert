package utils

import (
	"github.com/pkg/errors"
	"os"
	"path/filepath"
)

// CreateDir creates a local directory for certificates.
func CreateDir(path string) error {
	currDir, err := os.Getwd()
	if err != nil {
		return err
	}

	certsPath := filepath.Join(currDir, path)
	if _, err = os.Stat(certsPath); os.IsNotExist(err) {
		if err = os.MkdirAll(certsPath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}
	return errors.Errorf("directory: %s already exists", certsPath)
}
