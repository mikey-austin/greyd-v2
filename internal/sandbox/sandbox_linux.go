//go:build linux

/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package sandbox

import (
	"errors"
	"fmt"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/unix"
)

func apply(p Profile, log *slog.Logger) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if err := landlock(p, log); err != nil {
		if errors.Is(err, errNoLandlock) {
			log.Debug("landlock unavailable, filesystem not confined", "role", p.Role.String())
		} else {
			return fmt.Errorf("landlock: %w", err)
		}
	}
	if err := seccomp(p); err != nil {
		if errors.Is(err, errNoSeccomp) {
			log.Debug("seccomp unavailable on this architecture", "role", p.Role.String())
		} else {
			return fmt.Errorf("seccomp: %w", err)
		}
	}
	log.Debug("sandbox applied", "role", p.Role.String())
	return nil
}

var errNoLandlock = errors.New("landlock unavailable")

// Filesystem access rights handled by Landlock ABI 1, plus the later
// additions when the kernel supports them.
const (
	fsReadAccess = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	fsWriteBase  = unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	fsV1Access = fsReadAccess | fsWriteBase | unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK
)

func landlockSyscall(nr uintptr, a1, a2, a3 uintptr) (uintptr, error) {
	r, _, e := unix.Syscall(nr, a1, a2, a3)
	if e != 0 {
		return r, e
	}
	return r, nil
}

// landlock denies every filesystem access except the profile's paths.
// Open descriptors are unaffected, so logs and databases opened earlier
// keep working.
func landlock(p Profile, log *slog.Logger) error {
	abi, err := landlockSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			return errNoLandlock
		}
		return fmt.Errorf("abi version: %w", err)
	}
	handled := uint64(fsV1Access)
	write := uint64(fsWriteBase)
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
		write |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
		write |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 && !p.Devices {
		handled |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	// A helper program needs its interpreter and libraries, so a profile
	// that may exec keeps read and execute access everywhere and only
	// has writes confined.
	if p.Exec {
		handled &^= fsReadAccess | unix.LANDLOCK_ACCESS_FS_EXECUTE
	}
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	fd, err := landlockSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if err != nil {
		return fmt.Errorf("create ruleset: %w", err)
	}
	rs := int(fd)
	defer func() { _ = unix.Close(rs) }()

	addRule := func(path string, access uint64) error {
		pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				log.Debug("sandbox path does not exist, skipped", "path", path)
				return nil
			}
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer func() { _ = unix.Close(pfd) }()
		// A file (not a directory) cannot carry directory rights.
		var st unix.Stat_t
		if err := unix.Fstat(pfd, &st); err == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			access &^= unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
				unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
				unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
				unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
				unix.LANDLOCK_ACCESS_FS_REFER
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access & handled, Parent_fd: int32(pfd)}
		if _, err := landlockSyscall(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rs), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule))); err != nil {
			return fmt.Errorf("add rule %s: %w", path, err)
		}
		return nil
	}
	for _, path := range p.ReadPaths {
		if err := addRule(path, fsReadAccess); err != nil {
			return err
		}
	}
	for _, path := range p.WritePaths {
		if err := addRule(path, fsReadAccess|write); err != nil {
			return err
		}
	}
	if _, err := landlockSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rs), 0, 0); err != nil {
		return fmt.Errorf("restrict self: %w", err)
	}
	return nil
}

var errNoSeccomp = errors.New("seccomp filter not available for this architecture")

// seccomp installs a deny list: the process may no longer start programs
// (unless the profile allows it), trace, mount, load modules, change
// namespaces or root, reboot or use the kernel keyring and BPF
// facilities. Denied calls fail with EPERM; a foreign architecture is
// killed.
func seccomp(p Profile) error {
	if seccompArch == 0 {
		return errNoSeccomp
	}
	denied := deniedSyscalls
	if !p.Exec {
		denied = append(append([]uint32{}, denied...), unix.SYS_EXECVE, unix.SYS_EXECVEAT)
	}

	const (
		archOffset = 4 // offsetof(struct seccomp_data, arch)
		nrOffset   = 0 // offsetof(struct seccomp_data, nr)
	)
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
	}
	prog := []unix.SockFilter{
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, archOffset),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, seccompArch, 1, 0),
		stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, nrOffset),
	}
	// Each denied number jumps to the shared EPERM return at the end.
	for i, nr := range denied {
		remaining := len(denied) - i - 1
		prog = append(prog, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, uint8(remaining+1), 0))
	}
	prog = append(prog,
		stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
		stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
	)
	if len(denied) > 250 {
		return errors.New("deny list too long for an 8-bit jump")
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// TSYNC applies the filter to every thread of the Go runtime.
	if _, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); e != 0 {
		return e
	}
	return nil
}

// Confined reports whether a seccomp filter is active (tests).
func Confined() bool {
	v, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	return err == nil && v != 0
}
