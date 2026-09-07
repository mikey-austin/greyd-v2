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

package greydb

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	_ "github.com/mikey-austin/greyd-v2/internal/config/parse"
	"github.com/mikey-austin/greyd-v2/internal/grey"
	"github.com/mikey-austin/greyd-v2/internal/sync"
)

const testNow = int64(1_700_000_000)

func init() {
	nowFunc = func() time.Time { return time.Unix(testNow, 0) }
}

// writeConfig writes a configuration file using a fresh memory database
// named after the test and returns its path.
func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	memory.Reset(name)
	src := fmt.Sprintf("section database {\n  driver = \"memory\",\n  name = %q\n}\n%s", name, extra)
	path := filepath.Join(t.TempDir(), "greyd.conf")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAddWhiteAndList(t *testing.T) {
	cfg := writeConfig(t, "")
	if code, _, stderr := run(t, "-f", cfg, "-a", "1.2.3.4"); code != 0 {
		t.Fatalf("add: code %d, stderr %q", code, stderr)
	}
	code, stdout, _ := run(t, "-f", cfg)
	if code != 0 {
		t.Fatalf("list: code %d", code)
	}
	want := fmt.Sprintf("WHITE|1.2.3.4|||%d|%d|%d|1|0\n", testNow, testNow, testNow+grey.WhiteExp)
	if stdout != want {
		t.Fatalf("list output %q, want %q", stdout, want)
	}

	// Adding again updates the entry and increments pcount.
	if code, _, stderr := run(t, "-f", cfg, "-a", "1.2.3.4"); code != 0 {
		t.Fatalf("re-add: code %d, stderr %q", code, stderr)
	}
	_, stdout, _ = run(t, "-f", cfg)
	want = fmt.Sprintf("WHITE|1.2.3.4|||%d|%d|%d|1|1\n", testNow, testNow, testNow+grey.WhiteExp)
	if stdout != want {
		t.Fatalf("list output after update %q, want %q", stdout, want)
	}
}

func TestAddSpamtrap(t *testing.T) {
	cfg := writeConfig(t, "")
	if code, _, stderr := run(t, "-f", cfg, "-T", "-a", "<Trap@Example.ORG>"); code != 0 {
		t.Fatalf("add: code %d, stderr %q", code, stderr)
	}
	_, stdout, _ := run(t, "-f", cfg)
	if stdout != "SPAMTRAP|trap@example.org\n" {
		t.Fatalf("list output %q", stdout)
	}
}

func TestAddSpamtrapNotEmail(t *testing.T) {
	cfg := writeConfig(t, "")
	code, _, stderr := run(t, "-Ta", "-f", cfg, "notanaddress")
	if code != 1 || !strings.Contains(stderr, "Not an email address: notanaddress") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestAddDomain(t *testing.T) {
	cfg := writeConfig(t, "")
	if code, _, stderr := run(t, "-f", cfg, "-D", "-a", "@Greyd.org"); code != 0 {
		t.Fatalf("add: code %d, stderr %q", code, stderr)
	}
	_, stdout, _ := run(t, "-f", cfg)
	if stdout != "DOMAIN|@greyd.org\n" {
		t.Fatalf("list output %q", stdout)
	}
}

func TestAddTrapped(t *testing.T) {
	cfg := writeConfig(t, "")
	if code, _, stderr := run(t, "-f", cfg, "-t", "-a", "5.6.7.8"); code != 0 {
		t.Fatalf("add: code %d, stderr %q", code, stderr)
	}
	_, stdout, _ := run(t, "-f", cfg)
	want := fmt.Sprintf("TRAPPED|5.6.7.8|%d\n", testNow+grey.TrapExp)
	if stdout != want {
		t.Fatalf("list output %q, want %q", stdout, want)
	}
}

func TestDelete(t *testing.T) {
	cfg := writeConfig(t, "")
	run(t, "-f", cfg, "-a", "1.2.3.4", "5.6.7.8")
	if code, _, stderr := run(t, "-f", cfg, "-d", "1.2.3.4"); code != 0 {
		t.Fatalf("delete: code %d, stderr %q", code, stderr)
	}
	_, stdout, _ := run(t, "-f", cfg)
	if strings.Contains(stdout, "1.2.3.4") || !strings.Contains(stdout, "WHITE|5.6.7.8|") {
		t.Fatalf("list output after delete %q", stdout)
	}
}

func TestDeleteMissing(t *testing.T) {
	cfg := writeConfig(t, "")
	code, _, stderr := run(t, "-f", cfg, "-d", "1.2.3.4")
	if code != 1 || !strings.Contains(stderr, "No entry for 1.2.3.4") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestAddInvalidIP(t *testing.T) {
	cfg := writeConfig(t, "")
	code, _, stderr := run(t, "-f", cfg, "-a", "not-an-ip")
	if code != 1 || !strings.Contains(stderr, "Invalid IP address not-an-ip") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	// Failures are summed; one good and one bad key yields 1.
	code, _, _ = run(t, "-f", cfg, "-a", "1.1.1.1", "bad", "2.2.2.2")
	if code != 1 {
		t.Fatalf("mixed add code %d, want 1", code)
	}
}

func TestUsage(t *testing.T) {
	const want = "usage: greydb [-f config] [-s] [[-DTt] -a keys] [[-DTt] -d keys] \n"
	cfg := writeConfig(t, "")
	for _, args := range [][]string{
		{"-f", cfg, "-T"},
		{"-f", cfg, "-x"},
		{"-f"},
		{"-Y"},
	} {
		code, _, stderr := run(t, args...)
		if code != 1 || stderr != want {
			t.Errorf("args %v: code %d, stderr %q", args, code, stderr)
		}
	}
}

func TestAddNoKeys(t *testing.T) {
	cfg := writeConfig(t, "")
	code, _, stderr := run(t, "-f", cfg, "-a")
	if code != 0 || !strings.Contains(stderr, "No addresses specified") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
	// Empty arguments are skipped as well.
	code, _, stderr = run(t, "-f", cfg, "-a", "")
	if code != 0 || !strings.Contains(stderr, "No addresses specified") {
		t.Fatalf("empty key: code %d, stderr %q", code, stderr)
	}
}

func TestMissingConfig(t *testing.T) {
	code, _, stderr := run(t, "-f", filepath.Join(t.TempDir(), "missing.conf"))
	if code != 1 || stderr == "" {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestSyncTarget(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port

	cfg := writeConfig(t, fmt.Sprintf("section sync {\n  enable = 1,\n  verify = 0,\n  port = %d\n}\n", port))
	code, _, stderr := run(t, "-f", cfg, "-Y", "127.0.0.1", "-a", "9.9.9.9")
	if code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}

	buf := make([]byte, sync.MaxSize)
	_ = ln.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ln.Read(buf)
	if err != nil {
		t.Fatalf("no sync packet received: %v", err)
	}
	var key sync.Key
	pkt, err := sync.Decode(&key, buf[:n])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	entries := pkt.Entries
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Type != sync.TypeWhite || e.IP.String() != "9.9.9.9" || e.Delete {
		t.Fatalf("unexpected entry %+v", e)
	}
	if e.Expire != uint32(testNow+grey.WhiteExp) {
		t.Fatalf("expire %d, want %d", e.Expire, testNow+grey.WhiteExp)
	}
}

func TestSyncDisabled(t *testing.T) {
	cfg := writeConfig(t, "")
	code, _, stderr := run(t, "-f", cfg, "-Y", "127.0.0.1", "-a", "9.9.9.9")
	if code != 0 || !strings.Contains(stderr, "sync disabled by configuration") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}
