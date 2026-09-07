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

package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mikey-austin/greyd-v2/internal/config"
	"github.com/mikey-austin/greyd-v2/internal/settings"
	"github.com/mikey-austin/greyd-v2/internal/spamdlist"
)

// Fetch methods understood in a list's "method" variable.
const (
	MethodFile  = "file"
	MethodHTTP  = "http"
	MethodHTTPS = "https"
	MethodFTP   = "ftp"
	MethodFTPS  = "ftps"
	MethodExec  = "exec"

	// DefaultCurl is used when setup.curl_path is not configured.
	DefaultCurl = "/bin/curl"

	// maxListBytes bounds a downloaded list so a hostile or broken mirror
	// cannot exhaust memory or disk (curl --max-filesize). Compressed
	// lists are well under this.
	maxListBytes = 256 << 20
)

// Open returns the (decompressed, if gzip) contents of the list described
// by section, selecting the source as get_parser does in main_greyd_setup.c:
// "file" (or no method) opens a local file, "http"/"ftp" run curl and
// "exec" runs the "file" variable as a command line.
func Open(ctx context.Context, section *config.Section, cfg settings.Setup) (io.ReadCloser, error) {
	file := section.Str("file", "")
	if file == "" {
		return nil, errors.New("no file configuration variables set")
	}
	method := section.Str("method", "")

	var (
		rc  io.ReadCloser
		err error
	)
	switch method {
	case "", MethodFile:
		rc, err = os.Open(file)
	case MethodHTTP, MethodHTTPS, MethodFTP, MethodFTPS:
		curl := cfg.CurlPath
		if curl == "" {
			curl = DefaultCurl
		}
		// Fail on HTTP errors, bound the time and size, and restrict curl
		// to the requested scheme so a redirect cannot downgrade to a
		// different protocol (redirects are not followed at all: no -L).
		args := []string{
			"-sS", "--fail",
			"--proto", "=" + method,
			"--max-time", "300",
			"--max-filesize", strconv.Itoa(maxListBytes),
		}
		if proxy := cfg.CurlProxy; proxy != "" {
			args = append(args, "--proxy", proxy)
		}
		args = append(args, method+"://"+file)
		rc, err = openChild(ctx, curl, args...)
	case MethodExec:
		argv := strings.FieldsFunc(file, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(argv) == 0 {
			return nil, errors.New("no file configuration variables set")
		}
		rc, err = openChild(ctx, argv[0], argv[1:]...)
	default:
		return nil, fmt.Errorf("unknown method %s", method)
	}
	if err != nil {
		return nil, err
	}

	r, err := spamdlist.OpenMaybeGzip(rc)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	return &readCloser{Reader: r, closer: rc}, nil
}

// readCloser pairs a decompressing reader with the underlying source.
type readCloser struct {
	io.Reader
	closer io.Closer
}

func (r *readCloser) Close() error { return r.closer.Close() }

// childReader is a running command's stdout; Close reaps the process.
type childReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (c *childReader) Close() error {
	_ = c.ReadCloser.Close()
	return c.cmd.Wait()
}

// openChild starts name with args and returns its standard output
// (open_child).
func openChild(ctx context.Context, name string, args ...string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not execute %s: %w", name, err)
	}
	return &childReader{ReadCloser: out, cmd: cmd}, nil
}
