// Quantaureum Node source, version 1.0.0.
package safeconv

import (
	"errors"
	"path/filepath"
	"strings"
)

var (
	ErrPathTraversal = errors.New("path traversal detected")
	ErrAbsolutePath  = errors.New("unexpected absolute path")
)

func ValidateFilePath(path, baseDir string) (string, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return "", ErrPathTraversal
	}
	absPath, err := filepath.Abs(filepath.Join(baseDir, cleaned))
	if err != nil {
		return "", err
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absPath, absBase) {
		return "", ErrPathTraversal
	}
	return cleaned, nil
}

func ValidateOutputPath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return "", ErrPathTraversal
	}
	return cleaned, nil
}
