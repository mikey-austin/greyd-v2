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

//go:build unix

package logger

import "log/syslog"

type unixSyslog struct{ w *syslog.Writer }

func (u *unixSyslog) Write(sev Severity, msg string) error {
	switch sev {
	case SevCrit:
		return u.w.Crit(msg)
	case SevErr:
		return u.w.Err(msg)
	case SevWarning:
		return u.w.Warning(msg)
	case SevDebug:
		return u.w.Debug(msg)
	default:
		return u.w.Info(msg)
	}
}

func (u *unixSyslog) Close() error { return u.w.Close() }

func init() {
	openSyslog = func(ident string) (syslogSink, error) {
		w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, ident)
		if err != nil {
			return nil, err
		}
		return &unixSyslog{w: w}, nil
	}
}
