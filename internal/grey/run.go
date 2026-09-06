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

package grey

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/mikey-austin/greyd-golang/internal/config/parse"
	"github.com/mikey-austin/greyd-golang/internal/ipc"
	"github.com/mikey-austin/greyd-golang/internal/logger"
)

// RunReader consumes messages from in until it is closed or a malformed
// message arrives (Grey_start_reader). Cancelling ctx makes the loop exit
// at the next message; the caller should also close the reader to unblock
// it.
func (g *Greylister) RunReader(ctx context.Context, in io.Reader) error {
	r := ipc.NewReader(in)
	for {
		if ctx.Err() != nil {
			logger.Debug("stopping grey reader")
			return nil
		}
		m, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			var pe *parse.Error
			if errors.As(err, &pe) {
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			logger.Debug("error detected on grey_in: %v", err)
			return err
		}
		if err := g.ProcessMessage(m); err != nil {
			if errors.Is(err, ErrUnknownType) {
				return err
			}
			logger.Warning("grey message failed: %v", err)
		}
	}
}

// RunScanner runs ScanOnce every interval until ctx is done
// (Grey_start_scanner).
func (g *Greylister) RunScanner(ctx context.Context, interval time.Duration) error {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if err := g.ScanOnce(); err != nil {
			logger.Warning("db scan failed: %v", err)
		}
		t.Reset(interval)
	}
}
