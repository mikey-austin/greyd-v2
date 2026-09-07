package greyd

import (
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikey-austin/greyd-v2/adapters/db/memory"
	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/ipc"
)

// TestConfigHoldIdleConnection checks that a configuration connection that
// is opened and left idle is cut after cfgConnTimeout, so the next
// connection (a blacklist push) is served, and that SMTP service is not
// affected while the connection is held.
func TestConfigHoldIdleConnection(t *testing.T) {
	runConfigHold(t, "cfghold-idle", func(net.Conn) {})
}

// TestConfigHoldPartialFrame is the same with a client that sends the
// start of a frame and then stalls without the %% terminator.
func TestConfigHoldPartialFrame(t *testing.T) {
	runConfigHold(t, "cfghold-partial", func(c net.Conn) {
		if _, err := fmt.Fprintf(c, "name = \"stalled\"\nmessage = \"m\"\nips = [ \"9.9.9.9\""); err != nil {
			t.Errorf("partial write: %v", err)
		}
	})
}

func runConfigHold(t *testing.T, dbName string, hold func(net.Conn)) {
	t.Helper()
	const timeout = 500 * time.Millisecond
	saved := cfgConnTimeout
	cfgConnTimeout = timeout
	t.Cleanup(func() { cfgConnTimeout = saved })

	memory.Reset(dbName)
	sock := filepath.Join(t.TempDir(), "greyd.sock")
	cfg := testConfig(t, dbName, fmt.Sprintf("config_socket = %q\n", sock))
	r := startDaemon(t, cfg, Options{Opts: config.New()})

	// Keep SMTP busy for the whole test: every connection must get a
	// banner promptly.
	stopSMTP := make(chan struct{})
	var smtpWG sync.WaitGroup
	var smtpConns atomic.Int64
	smtpWG.Add(1)
	go func() {
		defer smtpWG.Done()
		for {
			select {
			case <-stopSMTP:
				return
			default:
			}
			c, err := net.DialTimeout("tcp", r.d.MainAddr().String(), 2*time.Second)
			if err != nil {
				t.Errorf("smtp dial during config hold: %v", err)
				return
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4)
			if _, err := c.Read(buf); err != nil || string(buf) != "220 " {
				t.Errorf("smtp banner during config hold: %q %v", buf, err)
				_ = c.Close()
				return
			}
			_ = c.Close()
			smtpConns.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Open the held connection; the daemon serves configuration
	// connections one at a time, so it now blocks in the reader.
	held, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	hold(held)
	// Give the accept loop time to pick the held connection up before the
	// pusher connects, so the push really queues behind it.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	pusher, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteBlacklist(pusher, "pushed", "msg %A", []string{"1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	_ = pusher.Close()

	bound := 2 * timeout
	deadline := start.Add(bound + 200*time.Millisecond) // scheduling slack
	var installedAfter time.Duration
	for {
		found := false
		for _, bl := range r.d.snapshotBlacklists() {
			if bl.Name == "pushed" && bl.Match(mustAddr("1.2.3.4")) {
				found = true
			}
		}
		if found {
			installedAfter = time.Since(start)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("blacklist not installed within %v of the push while a connection was held", time.Since(start))
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("blacklist installed %v after the push (timeout %v)", installedAfter, timeout)
	if installedAfter > bound {
		t.Errorf("blacklist installed after %v, want within %v", installedAfter, bound)
	}

	// The held connection was cut by the daemon.
	_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Error("held connection was not closed by the daemon")
	}
	// Nothing from the stalled frame was installed.
	for _, bl := range r.d.snapshotBlacklists() {
		if bl.Name == "stalled" {
			t.Error("partial frame must not install a blacklist")
		}
	}

	close(stopSMTP)
	smtpWG.Wait()
	if n := smtpConns.Load(); n < 5 {
		t.Errorf("only %d SMTP connections served during the hold", n)
	}
}
