package peercred

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			select {}
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := Get(conn.(*net.UnixConn))
	if errors.Is(err, ErrUnsupported) {
		t.Skip("unsupported platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	if c.UID != os.Getuid() {
		t.Fatalf("uid = %d, want %d", c.UID, os.Getuid())
	}
}
