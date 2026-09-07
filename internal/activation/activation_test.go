package activation

import (
	"net"
	"os"
	"strconv"
	"testing"
)

func TestListeners(t *testing.T) {
	if _, err := Listeners(); err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	f, err := tcp.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Move the descriptor to 3 the way a service manager would.
	if err := dup2(int(f.Fd()), firstFD); err != nil {
		t.Skipf("cannot place descriptor 3: %v", err)
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "smtp")
	ls, err := Listeners()
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 || ls[0].Name != "smtp" || ls[0].Addr().String() != tcp.Addr().String() {
		t.Fatalf("listeners %+v", ls)
	}
	_ = ls[0].Close()
	if os.Getenv("LISTEN_FDS") != "" {
		t.Fatal("environment not cleared")
	}
	t.Setenv("LISTEN_PID", "1")
	t.Setenv("LISTEN_FDS", "1")
	if ls, _ := Listeners(); ls != nil {
		t.Fatal("foreign LISTEN_PID must be ignored")
	}
}
