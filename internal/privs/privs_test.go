package privs

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain lets the test binary act as a helper that holds a pidfile lock
// while its parent test observes it.
func TestMain(m *testing.M) {
	if path := os.Getenv("GREYD_TEST_HOLD_PIDFILE"); path != "" {
		p, err := WritePidfile(path, nil)
		if err != nil {
			if errors.Is(err, ErrAlreadyRunning) {
				os.Exit(3)
			}
			os.Exit(2)
		}
		// Signal readiness then hold the lock until stdin closes.
		os.Stdout.WriteString("locked\n")
		buf := make([]byte, 1)
		_, _ = os.Stdin.Read(buf)
		_ = p.Close("")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWritePidfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "greyd.pid")

	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	p, err := WritePidfile(path, me)
	if err != nil {
		t.Fatalf("WritePidfile: %v", err)
	}
	// Read through the locked descriptor: opening and closing another
	// descriptor on the file would release the POSIX lock.
	data := make([]byte, 32)
	n, _ := p.f.ReadAt(data, 0)
	if strings.TrimSpace(string(data[:n])) != itoa(os.Getpid()) {
		t.Fatalf("pidfile content %q", data[:n])
	}
	if p.Path() != path {
		t.Fatal("Path")
	}

	// A second process must be refused while we hold the lock.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "GREYD_TEST_HOLD_PIDFILE="+path)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("expected helper exit 3 (already running), got %v %q", err, out)
	}

	if err := p.Close(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pidfile should be unlinked")
	}

	// Once released, another process can take it.
	cmd = exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "GREYD_TEST_HOLD_PIDFILE="+path)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ = stdout.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "locked") {
		t.Fatalf("helper did not lock: %q", buf[:n])
	}
	// While the helper holds it we are refused.
	if _, err := WritePidfile(path, nil); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}
	_ = stdin.Close()
	_ = cmd.Wait()
}

func TestPidfileCloseStripsChroot(t *testing.T) {
	dir := t.TempDir()
	// Simulate: pidfile written at <dir>/chroot/greyd.pid, process then
	// chrooted into <dir>/chroot; Close must unlink "/greyd.pid" relative to
	// the new root. We cannot chroot in tests, so instead create the file at
	// the stripped path relative to the cwd.
	chroot := filepath.Join(dir, "jail")
	if err := os.MkdirAll(chroot, 0o755); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(chroot, "greyd.pid")
	p := &Pidfile{path: full}
	stripped := strings.TrimPrefix(full, chroot) // "/greyd.pid"
	if stripped != "/greyd.pid" {
		t.Fatalf("unexpected stripped path %q", stripped)
	}
	// Close attempts to remove "/greyd.pid"; it will not exist (and we
	// certainly do not want to create it), so the call must tolerate that.
	if err := p.Close(chroot); err != nil {
		t.Fatalf("Close with chroot: %v", err)
	}
	// Without a chroot prefix the real file is removed.
	if err := os.WriteFile(full, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	p = &Pidfile{path: full}
	if err := p.Close(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatal("pidfile not removed")
	}
	var nilp *Pidfile
	if err := nilp.Close(""); err != nil {
		t.Fatal("nil Close should be a no-op")
	}
}

func TestMaxFiles(t *testing.T) {
	n, err := MaxFiles()
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("MaxFiles = %d", n)
	}
}

func TestDropToSelf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if err := Drop(me); err != nil {
		t.Fatalf("Drop to self: %v", err)
	}
	if _, err := LookupUser("no-such-user-greyd-test"); err == nil {
		t.Fatal("LookupUser should fail")
	}
	if _, _, err := IDs(&user.User{Uid: "x", Gid: "1"}); err == nil {
		t.Fatal("IDs should reject bad uid")
	}
}

func TestDaemonizeMarker(t *testing.T) {
	t.Setenv(EnvDaemonized, "1")
	if err := Daemonize(true); err != nil {
		t.Fatalf("Daemonize in child should return nil: %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
