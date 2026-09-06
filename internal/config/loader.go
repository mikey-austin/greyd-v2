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

package config

import (
	"fmt"
	"os"
)

// Parser is the function used to parse configuration text into a Config.
// It is installed by the parse sub-package to avoid an import cycle.
var Parser func(cfg *Config, src string) error

// LoadFile parses the named file into c and then processes any queued
// include files, each at most once. Included files are parsed after the
// including file completes, so their definitions override earlier ones.
func (c *Config) LoadFile(path string) error {
	if Parser == nil {
		return fmt.Errorf("config: no parser installed")
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error opening file source: %w", err)
		}
		if err := Parser(c, string(data)); err != nil {
			return fmt.Errorf("parse error processing %s, %w", path, err)
		}
		c.MarkProcessed(path)
	}

	for {
		inc, ok := c.popInclude()
		if !ok {
			return nil
		}
		if c.Processed(inc) {
			continue
		}
		if err := c.LoadFile(inc); err != nil {
			return err
		}
	}
}
