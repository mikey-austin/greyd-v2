#!/usr/bin/env python3
"""Minimal SMTP client for the greyd integration harnesses.

Runs one greyd dialogue (banner, EHLO, MAIL FROM, RCPT TO, DATA and, when
greyd asks for it, a short body) and checks the final reply against the
expected code and, optionally, a text fragment. The transcript is printed
to stderr so that it ends up in the harness log.

Exit status: 0 when the final reply matches, 1 when it does not, 2 on a
connection or protocol error.
"""

import argparse
import socket
import sys
import time


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# Number of reply lines received with a bare LF instead of CRLF.
bare_lf = 0


class Dialogue:
    def __init__(self, sock, deadline):
        self.sock = sock
        self.deadline = deadline
        self.buf = b""

    def reply(self):
        """Read one (possibly multi-line) reply and return (code, lines).

        Lines are split on LF; a missing CR before it is tolerated but
        reported, since SMTP requires CRLF.
        """
        while True:
            lines = self.buf.split(b"\n")
            # Every complete line but the trailing partial one.
            complete = lines[:-1]
            for i, line in enumerate(complete):
                bare = line.rstrip(b"\r")
                # A line "NNN " (space, not dash) ends the reply.
                if len(bare) >= 4 and bare[:3].isdigit() and bare[3:4] == b" ":
                    consumed = complete[: i + 1]
                    self.buf = b"\n".join(lines[i + 1 :])
                    text = []
                    for l in consumed:
                        if not l.endswith(b"\r"):
                            global bare_lf
                            bare_lf += 1
                        text.append(l.rstrip(b"\r").decode("utf-8", "replace"))
                    for t in text:
                        log("S: " + t)
                    return text[-1][:3], text
            remaining = self.deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for a reply; buffer %r" % self.buf)
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed; buffer %r" % self.buf)
            self.buf += chunk

    def send(self, line):
        log("C: " + line)
        self.sock.sendall((line + "\r\n").encode())


def run(args):
    deadline = time.time() + args.timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    if args.src:
        sock.bind((args.src, 0))
    sock.connect((args.dst, args.port))
    d = Dialogue(sock, deadline)

    code, _ = d.reply()
    if code != "220":
        raise RuntimeError("expected a 220 banner, got %s" % code)
    d.send("EHLO " + args.helo)
    code, _ = d.reply()
    if code != "250":
        raise RuntimeError("EHLO: expected 250, got %s" % code)
    d.send("MAIL FROM:<%s>" % args.mail_from)
    code, _ = d.reply()
    if code != "250":
        raise RuntimeError("MAIL FROM: expected 250, got %s" % code)
    d.send("RCPT TO:<%s>" % args.rcpt_to)
    code, _ = d.reply()
    if code != "250":
        raise RuntimeError("RCPT TO: expected 250, got %s" % code)
    d.send("DATA")
    code, lines = d.reply()
    if code == "354":
        # Blacklisted clients (and any MTA-like path) get the verdict
        # after the message body.
        d.send("Subject: greyd integration")
        d.send("")
        d.send("test")
        d.send(".")
        code, lines = d.reply()
    try:
        d.send("QUIT")
    except OSError:
        pass
    sock.close()

    if bare_lf:
        log("WARNING: %d reply line(s) ended in a bare LF instead of CRLF" % bare_lf)
    text = "\n".join(lines)
    if code != args.expect:
        log("final reply %s, expected %s" % (code, args.expect))
        return 1
    if args.expect_text and args.expect_text not in text:
        log("final reply lacks %r" % args.expect_text)
        return 1
    log("final reply %s as expected" % code)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dst", default="127.0.0.1", help="address to connect to")
    p.add_argument("--port", type=int, default=2525)
    p.add_argument("--src", default=None, help="local address to bind before connecting")
    p.add_argument("--expect", default="451", help="expected final reply code")
    p.add_argument("--expect-text", default=None, help="fragment the final reply must contain")
    p.add_argument("--helo", default="it.example.test")
    p.add_argument("--mail-from", default="sender@example.test")
    p.add_argument("--rcpt-to", default="rcpt@example.test")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()
    try:
        return run(args)
    except (OSError, RuntimeError) as e:
        log("smtpcheck: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
