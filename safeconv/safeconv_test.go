// Quantaureum Node source, version 1.0.0.
package safeconv

import (
	"math"
	"strings"
	"testing"
)

func TestUint64ToInt64(t *testing.T) {
	tests := []struct {
		name    string
		v       uint64
		want    int64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small", 100, 100, false},
		{"max_int64", math.MaxInt64, math.MaxInt64, false},
		{"overflow", math.MaxInt64 + 1, 0, true},
		{"huge", math.MaxUint64, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint64ToInt64(tt.v)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUint64ToInt64Safe(t *testing.T) {
	tests := []struct {
		name string
		v    uint64
		want int64
	}{
		{"normal", 100, 100},
		{"max", math.MaxInt64, math.MaxInt64},
		{"overflow", math.MaxInt64 + 1, math.MaxInt64},
		{"huge", math.MaxUint64, math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Uint64ToInt64Safe(tt.v)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUint64ToUint32(t *testing.T) {
	tests := []struct {
		name    string
		v       uint64
		want    uint32
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small", 100, 100, false},
		{"max_uint32", math.MaxUint32, math.MaxUint32, false},
		{"overflow", math.MaxUint32 + 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint64ToUint32(tt.v)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUint64ToUint32Safe(t *testing.T) {
	tests := []struct {
		name string
		v    uint64
		want uint32
	}{
		{"normal", 100, 100},
		{"max", math.MaxUint32, math.MaxUint32},
		{"overflow", math.MaxUint32 + 1, math.MaxUint32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Uint64ToUint32Safe(tt.v)
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUint64ToUint8(t *testing.T) {
	tests := []struct {
		name    string
		v       uint64
		want    uint8
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small", 100, 100, false},
		{"max_uint8", math.MaxUint8, math.MaxUint8, false},
		{"overflow", math.MaxUint8 + 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint64ToUint8(tt.v)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUint64ToInt(t *testing.T) {
	tests := []struct {
		name    string
		v       uint64
		wantErr bool
	}{
		{"small", 100, false},
		{"max", uint64(math.MaxInt), false},
		{"overflow", uint64(math.MaxInt) + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Uint64ToInt(tt.v)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestUint64ToIntSafe(t *testing.T) {
	got := Uint64ToIntSafe(100)
	if got != 100 {
		t.Errorf("got %d, want 100", got)
	}
}

func TestUint64ToIntSafe_Overflow(t *testing.T) {
	got := Uint64ToIntSafe(math.MaxUint64)
	if got != math.MaxInt {
		t.Errorf("got %d, want %d", got, math.MaxInt)
	}
}

func TestInt64ToUint64(t *testing.T) {
	tests := []struct {
		name    string
		v       int64
		want    uint64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small", 100, 100, false},
		{"negative", -1, 0, true},
		{"max_int64", math.MaxInt64, math.MaxInt64, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Int64ToUint64(tt.v)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	tests := []struct {
		name    string
		path    string
		baseDir string
		wantErr bool
		errType error
	}{
		{"simple_file", "test.txt", tmpDir, false, nil},
		{"subdirectory", "sub/file.txt", tmpDir, false, nil},
		{"dot_current", "./file.txt", tmpDir, false, nil},
		{"empty_path", "", tmpDir, false, nil},
		{"traversal_dotdot", "../etc/passwd", tmpDir, true, ErrPathTraversal},
		{"traversal_leading", "../../etc/passwd", tmpDir, true, ErrPathTraversal},
		{"nested_file", "a/b/c/file.txt", tmpDir, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateFilePath(tt.path, tt.baseDir)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("expected %v, got %v", tt.errType, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got == "" && tt.path != "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestValidateOutputPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"simple", "output.txt", false},
		{"with_subdir", "sub/output.txt", false},
		{"clean_dot", "./output.txt", false},
		{"traversal_dotdot", "../etc/passwd", true},
		{"traversal_middle", "a/../../etc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateOutputPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
					return
				}
				if err != ErrPathTraversal {
					t.Errorf("expected ErrPathTraversal, got %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got == "" {
				t.Error("expected non-empty result")
			}
			if strings.Contains(got, "..") {
				t.Error("result should not contain ..")
			}
		})
	}
}

func TestErrOverflow(t *testing.T) {
	if ErrOverflow.Error() != "integer overflow" {
		t.Errorf("unexpected message: %s", ErrOverflow.Error())
	}
}

func TestErrPathTraversal(t *testing.T) {
	if ErrPathTraversal.Error() != "path traversal detected" {
		t.Errorf("unexpected message: %s", ErrPathTraversal.Error())
	}
}

func TestErrAbsolutePath(t *testing.T) {
	if ErrAbsolutePath.Error() != "unexpected absolute path" {
		t.Errorf("unexpected message: %s", ErrAbsolutePath.Error())
	}
}
