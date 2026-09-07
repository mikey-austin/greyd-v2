//go:build linux && (amd64 || arm64)

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
	"runtime"

	"golang.org/x/sys/unix"
)

var seccompArch = map[string]uint32{
	"amd64": unix.AUDIT_ARCH_X86_64,
	"arm64": unix.AUDIT_ARCH_AARCH64,
}[runtime.GOARCH]

// deniedSyscalls exist on both supported architectures.
var deniedSyscalls = []uint32{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_REBOOT, unix.SYS_ACCT,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_OPEN_BY_HANDLE_AT,
	unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
}

// allowedSyscalls is the strict profile: what the Go runtime, the
// standard library's net, os and time packages and the database drivers
// use once a process is running. exec and wait are added for profiles
// that run helpers. Anything else fails with EPERM.
var allowedSyscalls = append([]uint32{
	// Memory and scheduling (Go runtime).
	unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MADVISE, unix.SYS_MREMAP, unix.SYS_MSYNC,
	unix.SYS_MINCORE, unix.SYS_MEMBARRIER, unix.SYS_BRK, unix.SYS_FUTEX, unix.SYS_FUTEX_WAITV,
	unix.SYS_CLONE, unix.SYS_CLONE3, unix.SYS_SET_ROBUST_LIST, unix.SYS_SET_TID_ADDRESS, unix.SYS_RSEQ,
	unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP,
	unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES, unix.SYS_GETTIMEOFDAY,
	unix.SYS_TIMER_CREATE, unix.SYS_TIMER_SETTIME, unix.SYS_TIMER_GETTIME, unix.SYS_TIMER_DELETE,
	unix.SYS_SETITIMER, unix.SYS_GETITIMER, unix.SYS_PRCTL, unix.SYS_GETRANDOM, unix.SYS_UNAME, unix.SYS_SYSINFO,
	unix.SYS_GETRLIMIT, unix.SYS_SETRLIMIT, unix.SYS_PRLIMIT64, unix.SYS_RESTART_SYSCALL,
	// Signals, threads and process identity.
	unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGTIMEDWAIT,
	unix.SYS_SIGALTSTACK, unix.SYS_TGKILL, unix.SYS_TKILL, unix.SYS_KILL, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETTID, unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID,
	unix.SYS_GETEGID, unix.SYS_GETGROUPS, unix.SYS_CAPGET, unix.SYS_PIDFD_OPEN, unix.SYS_PIDFD_SEND_SIGNAL,
	unix.SYS_WAIT4, unix.SYS_WAITID,
	// Descriptors and files.
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_PREAD64, unix.SYS_PWRITE64,
	unix.SYS_PREADV, unix.SYS_PWRITEV, unix.SYS_CLOSE, unix.SYS_CLOSE_RANGE, unix.SYS_OPENAT, unix.SYS_OPENAT2,
	unix.SYS_NEWFSTATAT, unix.SYS_FSTAT, unix.SYS_STATX, unix.SYS_LSEEK, unix.SYS_GETDENTS64,
	unix.SYS_FCNTL, unix.SYS_IOCTL, unix.SYS_FLOCK, unix.SYS_FSYNC, unix.SYS_FDATASYNC, unix.SYS_FTRUNCATE,
	unix.SYS_FALLOCATE, unix.SYS_FADVISE64, unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT,
	unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT, unix.SYS_RENAMEAT,
	unix.SYS_RENAMEAT2, unix.SYS_READLINKAT, unix.SYS_GETCWD, unix.SYS_UMASK, unix.SYS_DUP, unix.SYS_DUP3,
	unix.SYS_PIPE2, unix.SYS_EVENTFD2, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT,
	unix.SYS_EPOLL_PWAIT2, unix.SYS_PPOLL, unix.SYS_PSELECT6, unix.SYS_SENDFILE, unix.SYS_SPLICE,
	unix.SYS_COPY_FILE_RANGE,
	// Sockets.
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_ACCEPT4, unix.SYS_BIND, unix.SYS_LISTEN,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT, unix.SYS_SENDTO,
	unix.SYS_RECVFROM, unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_SENDMMSG, unix.SYS_RECVMMSG, unix.SYS_SHUTDOWN,
}, archSyscalls...)
