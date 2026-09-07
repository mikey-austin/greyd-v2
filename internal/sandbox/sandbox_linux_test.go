//go:build linux

package sandbox

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestHelperProcess is re-executed by TestApply with SANDBOX_HELPER set;
// it confines itself and reports what still works on stdout.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("SANDBOX_HELPER")
	if mode == "" {
		return
	}
	// Under the race detector the binary links cgo and the sandbox can
	// only confine the calling thread; keep the checks on that thread.
	runtime.LockOSThread()
	allowed := os.Getenv("SANDBOX_ALLOWED")
	p := Profile{Role: RoleGrey, WritePaths: []string{allowed}, ReadPaths: []string{"/etc/hostname"}}
	if mode == "exec" {
		p.Exec = true
	}
	// Listeners are bound before confinement; the profile then permits
	// connecting to the first only.
	var lnOK, lnDenied net.Listener
	if mode == "strict" {
		p.Strict = true
		var err error
		if lnOK, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			os.Stdout.WriteString("apply-error: " + err.Error() + "\n")
			os.Exit(0)
		}
		if lnDenied, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			os.Stdout.WriteString("apply-error: " + err.Error() + "\n")
			os.Exit(0)
		}
		p.ConnectPorts = []uint16{uint16(lnOK.Addr().(*net.TCPAddr).Port)}
	}
	if err := Apply(p, slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
		os.Stdout.WriteString("apply-error: " + err.Error() + "\n")
		os.Exit(0)
	}
	var out []string
	report := func(name string, err error) {
		switch {
		case err == nil:
			out = append(out, name+"=ok")
		case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
			out = append(out, name+"=denied")
		default:
			out = append(out, name+"=err:"+err.Error())
		}
	}
	_, err := os.ReadFile("/etc/hostname")
	report("read-allowed", err)
	_, err = os.ReadFile("/etc/passwd")
	report("read-denied", err)
	err = os.WriteFile(filepath.Join(allowed, "f"), []byte("x"), 0o600)
	report("write-allowed", err)
	err = os.WriteFile(filepath.Join(os.TempDir(), "sandbox-denied-"+filepath.Base(allowed)), []byte("x"), 0o600)
	report("write-denied", err)
	err = exec.Command("/bin/true").Run()
	report("exec", err)
	if err != nil {
		out = append(out, "execerr="+err.Error())
	}
	if mode == "strict" {
		report("net", exerciseNet(lnOK))
		_, err := net.Dial("tcp", lnDenied.Addr().String())
		report("netdeny", err)
		report("threads", exerciseThreads())
	}
	if Confined() {
		out = append(out, "seccomp=on")
	}
	os.Stdout.WriteString(strings.Join(out, " ") + "\n")
	os.Exit(0)
}

// exerciseNet accepts on ln, connects to it and exchanges a byte, and
// sends a UDP datagram, which covers the socket calls Go uses.
func exerciseNet(ln net.Listener) error {
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte{1})
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Read(make([]byte, 1)); err != nil {
		return err
	}
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer u.Close()
	_, err = u.WriteTo([]byte{1}, u.LocalAddr())
	return err
}

// exerciseThreads forces new OS threads, timers and a GC cycle.
func exerciseThreads() error {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			time.Sleep(5 * time.Millisecond)
			runtime.UnlockOSThread()
		}()
	}
	wg.Wait()
	runtime.GC()
	return nil
}

func runHelper(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "SANDBOX_HELPER="+mode, "SANDBOX_ALLOWED="+dir)
	outb, err := cmd.CombinedOutput()
	out := string(outb)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "apply-error") {
		if strings.Contains(out, "landlock unavailable") || strings.Contains(out, "seccomp unavailable") {
			t.Skipf("sandbox not applicable here: %s", out)
		}
		t.Fatalf("sandbox failed: %s", out)
	}
	return out
}

func TestApply(t *testing.T) {
	if _, err := os.Stat("/etc/hostname"); err != nil {
		t.Skip("no /etc/hostname")
	}
	out := runHelper(t, "noexec")
	landlock := !strings.Contains(out, "landlock unavailable")
	for _, want := range []string{"read-allowed=ok", "write-allowed=ok", "seccomp=on", "exec=denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if landlock {
		for _, want := range []string{"read-denied=denied", "write-denied=denied"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in %q", want, out)
			}
		}
	}
	out = runHelper(t, "exec")
	if !strings.Contains(out, "exec=ok") {
		t.Errorf("exec profile should allow programs: %q", out)
	}
	out = runHelper(t, "strict")
	for _, want := range []string{"read-allowed=ok", "write-allowed=ok", "seccomp=on", "exec=denied", "net=ok", "threads=ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("strict: missing %q in %q", want, out)
		}
	}
	// Landlock network rules (ABI 4) deny connects to other ports.
	if landlock && !strings.Contains(out, "landlock ABI too old") {
		want := "netdeny=denied"
		if !strings.Contains(out, want) {
			t.Errorf("strict: missing %q in %q", want, out)
		}
	}
}
