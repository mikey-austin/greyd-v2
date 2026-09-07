//go:build linux

package sandbox

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestHelperProcess is re-executed by TestApply with SANDBOX_HELPER set;
// it confines itself and reports what still works on stdout.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("SANDBOX_HELPER")
	if mode == "" {
		return
	}
	allowed := os.Getenv("SANDBOX_ALLOWED")
	p := Profile{Role: RoleGrey, WritePaths: []string{allowed}, ReadPaths: []string{"/etc/hostname"}}
	if mode == "exec" {
		p.Exec = true
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
	if Confined() {
		out = append(out, "seccomp=on")
	}
	os.Stdout.WriteString(strings.Join(out, " ") + "\n")
	os.Exit(0)
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
		t.Skipf("sandbox not applicable here: %s", out)
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
}
