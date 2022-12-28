package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateDir(t *testing.T) {
	t.Parallel()
	currDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("CreateDir", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			dir string
		}{
			{"tmp/dir01"},
			{"tmp/dir02"},
			{"tmp/dir03"},
		}
		for _, tc := range testCases {
			err = CreateDir(tc.dir)
			assert.NoError(t, err)
			_, err = os.Stat(filepath.Join(currDir, tc.dir))
			assert.NoError(t, err)
		}
	})
	t.Run("CreateDirErrorAlreadyExists", func(t *testing.T) {
		t.Parallel()
		err = CreateDir("tmp/dir04")
		assert.NoError(t, err)
		err = CreateDir("tmp/dir04")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}
