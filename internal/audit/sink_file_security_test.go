package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFileSink_RejectUnsafeConfiguredModes(t *testing.T) {
	for _, mode := range []fs.FileMode{0, 0400, 0660, 0666, 0644, 0604, 0700, 0601, fs.ModeSetuid | 0600} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			sink := NewFileSinkWithMode(path, mode)
			require.ErrorContains(t, sink.WriteEvent(&AuditEvent{Operation: "must not persist"}), "unsafe audit file mode")
			_, err := os.Lstat(path)
			require.True(t, os.IsNotExist(err), "invalid mode must not create a destination, got %v", err)
		})
	}
}

func TestFileSink_RejectSymlinkDestination(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing_target", true: "dangling_target"}[dangling], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target.log")
			const original = "existing protected content\n"
			if !dangling {
				require.NoError(t, os.WriteFile(target, []byte(original), 0600))
			}
			path := filepath.Join(dir, "audit.log")
			require.NoError(t, os.Symlink(target, path))
			require.ErrorContains(t, NewFileSink(path).WriteEvent(&AuditEvent{Operation: "must not follow"}), "must be a regular file")
			if dangling {
				_, err := os.Stat(target)
				require.True(t, os.IsNotExist(err), "symlink target must not be created")
			} else {
				data, err := os.ReadFile(target)
				require.NoError(t, err)
				require.Equal(t, original, string(data), "symlink target must not be modified")
			}
		})
	}
}

func TestFileSink_RejectNonregularDestination(t *testing.T) {
	for _, kind := range []string{"directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if kind == "directory" {
				require.NoError(t, os.Mkdir(path, 0700))
			} else {
				require.NoError(t, unix.Mkfifo(path, 0600))
			}
			require.ErrorContains(t, NewFileSink(path).WriteEvent(&AuditEvent{Operation: "must not persist"}), "must be a regular file")
		})
	}
}

func TestFileSink_ExistingPermissions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured fs.FileMode
		existing   fs.FileMode
		ok         bool
	}{
		{"default_private", 0600, 0600, true},
		{"group_read_override", 0640, 0640, true},
		{"stricter_existing_private", 0640, 0600, true},
		{"default_rejects_existing_group_read", 0600, 0640, false},
		{"group_write", 0640, 0660, false},
		{"world_read", 0640, 0644, false},
		{"world_write", 0640, 0602, false},
		{"owner_execute", 0600, 0700, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			const original = "original content\n"
			require.NoError(t, os.WriteFile(path, []byte(original), 0600))
			require.NoError(t, os.Chmod(path, tc.existing))
			sink := NewFileSinkWithMode(path, tc.configured)
			err := sink.WriteEvent(&AuditEvent{Operation: "append only if safe"})
			data, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			if tc.ok {
				require.NoError(t, err)
				require.Contains(t, string(data), "append only if safe")
				require.Contains(t, string(data), original)
			} else {
				require.Error(t, err)
				require.Equal(t, original, string(data), "unsafe existing file must remain unmodified")
			}
			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, tc.existing, info.Mode().Perm(), "do not silently chmod operator files")
		})
	}
}

func TestFileSink_RechecksDestinationOnEveryWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink := NewFileSink(path)
	require.NoError(t, sink.WriteEvent(&AuditEvent{Operation: "first safe write"}))
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(path, 0644))
	require.Error(t, sink.WriteEvent(&AuditEvent{Operation: "must not append"}))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
