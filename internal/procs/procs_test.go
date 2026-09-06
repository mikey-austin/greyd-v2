package procs

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
)

// TestMain doubles as the child role "echo": it reads lines from the
// inherited "in" descriptor and writes them upper-cased to "out".
func TestMain(m *testing.M) {
	if Role() == "echo" {
		in, err := InheritedFile("in")
		if err != nil {
			os.Exit(2)
		}
		out, err := InheritedFile("out")
		if err != nil {
			os.Exit(3)
		}
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			_, _ = io.WriteString(out, strings.ToUpper(sc.Text())+"\n")
		}
		if os.Getenv("EXTRA_FLAG") != "yes" {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSpawnRoundTrip(t *testing.T) {
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := Spawn{
		Role:  "echo",
		Files: map[string]*os.File{"in": inR, "out": outW},
		Env:   []string{"EXTRA_FLAG=yes"},
		Args:  []string{"-test.run=^$"},
	}.Start()
	if err != nil {
		t.Fatal(err)
	}
	_ = inR.Close()
	_ = outW.Close()

	if _, err := io.WriteString(inW, "hello\nworld\n"); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	data, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "HELLO\nWORLD\n" {
		t.Fatalf("child output %q", data)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child exit: %v", err)
	}
}

func TestInheritedFileErrors(t *testing.T) {
	if _, err := InheritedFile("missing"); err == nil {
		t.Fatal("missing descriptor must error")
	}
	t.Setenv("GREYD_FD_BAD", "x")
	if _, err := InheritedFile("bad"); err == nil {
		t.Fatal("bad descriptor must error")
	}
	t.Setenv("GREYD_FD_LOW", "1")
	if _, err := InheritedFile("low"); err == nil {
		t.Fatal("descriptor below 3 must error")
	}
}

func TestRoleAndFilterEnv(t *testing.T) {
	t.Setenv(EnvRole, "")
	if Role() != "" {
		t.Fatal("parent role should be empty")
	}
	env := []string{"A=1", "GREYD_ROLE=x", "GREYD_FD_IN=3", "B=2"}
	got := filterEnv(env, EnvRole, envFDPrefix)
	if len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Fatalf("filterEnv = %v", got)
	}
}
