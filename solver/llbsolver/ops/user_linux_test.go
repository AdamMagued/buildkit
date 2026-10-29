//go:build linux

package ops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/sys/user"
	"github.com/stretchr/testify/require"
)

type mockMountable struct {
	dir string
}

func (m *mockMountable) Mount() ([]mount.Mount, func() error, error) {
	return []mount.Mount{
		{
			Type:   "bind",
			Source: m.dir,
		},
	}, func() error { return nil }, nil
}

func (m *mockMountable) IdentityMapping() *user.IdentityMapping {
	return nil
}

func TestReadUser(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	require.NoError(t, os.MkdirAll(etcDir, 0755))

	passwdContent := "root:x:0:0:root:/root:/bin/sh\n" +
		"alice:x:1001:1002:Alice:/home/alice:/bin/sh\n"
	require.NoError(t, os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(passwdContent), 0644))

	groupContent := "root:x:0:\n" +
		"alicegroup:x:1002:\n" +
		"bobgroup:x:2000:\n"
	require.NoError(t, os.WriteFile(filepath.Join(etcDir, "group"), []byte(groupContent), 0644))

	mnt := &mockMountable{dir: dir}

	t.Run("nil chopt", func(t *testing.T) {
		u, err := readUser(nil, mnt, mnt)
		require.NoError(t, err)
		require.Nil(t, u)
	})

	t.Run("numeric uid and gid", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1001}},
		}
		u, err := readUser(chopt, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 1000, u.UID)
		require.Equal(t, 1001, u.GID)
	})

	t.Run("numeric uid only defaults gid to uid", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User: &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
		}
		u, err := readUser(chopt, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 1000, u.UID)
		require.Equal(t, 1000, u.GID)
	})

	t.Run("large numeric uid above int32 max", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 2147483648}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 4294967295}},
		}
		u, err := readUser(chopt, nil, nil)
		require.NoError(t, err)
		require.Equal(t, int(uint32(2147483648)), u.UID)
		require.Equal(t, int(uint32(4294967295)), u.GID)
	})

	t.Run("named user found", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "alice"}}},
		}
		u, err := readUser(chopt, mnt, nil)
		require.NoError(t, err)
		require.Equal(t, 1001, u.UID)
		require.Equal(t, 1002, u.GID)
	})

	t.Run("named user and named group found", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "alice"}}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "bobgroup"}}},
		}
		u, err := readUser(chopt, mnt, mnt)
		require.NoError(t, err)
		require.Equal(t, 1001, u.UID)
		require.Equal(t, 2000, u.GID)
	})

	t.Run("numeric user with named group found", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "bobgroup"}}},
		}
		u, err := readUser(chopt, nil, mnt)
		require.NoError(t, err)
		require.Equal(t, 1000, u.UID)
		require.Equal(t, 2000, u.GID)
	})

	t.Run("named user not found in passwd", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "nosuchuser"}}},
		}
		_, err := readUser(chopt, mnt, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, `user "nosuchuser" not found in /etc/passwd`)
	})

	t.Run("named group not found in group", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "alice"}}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "nosuchgroup"}}},
		}
		_, err := readUser(chopt, mnt, mnt)
		require.Error(t, err)
		require.ErrorContains(t, err, `group "nosuchgroup" not found in /etc/group`)
	})

	t.Run("numeric user with named group not found", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "nosuchgroup"}}},
		}
		_, err := readUser(chopt, nil, mnt)
		require.Error(t, err)
		require.ErrorContains(t, err, `group "nosuchgroup" not found in /etc/group`)
	})

	t.Run("missing passwd file", func(t *testing.T) {
		emptyDir := t.TempDir()
		emptyMnt := &mockMountable{dir: emptyDir}
		chopt := &pb.ChownOpt{
			User: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "alice"}}},
		}
		_, err := readUser(chopt, emptyMnt, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "/etc/passwd")
	})

	t.Run("missing group file", func(t *testing.T) {
		emptyDir := t.TempDir()
		emptyMnt := &mockMountable{dir: emptyDir}
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "bobgroup"}}},
		}
		_, err := readUser(chopt, nil, emptyMnt)
		require.Error(t, err)
		require.ErrorContains(t, err, "/etc/group")
	})

	t.Run("missing user mount", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "alice"}}},
		}
		_, err := readUser(chopt, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid missing user mount")
	})

	t.Run("missing group mount", func(t *testing.T) {
		chopt := &pb.ChownOpt{
			User:  &pb.UserOpt{User: &pb.UserOpt_ByID{ByID: 1000}},
			Group: &pb.UserOpt{User: &pb.UserOpt_ByName{ByName: &pb.NamedUserOpt{Name: "bobgroup"}}},
		}
		_, err := readUser(chopt, nil, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid missing group mount")
	})
}
