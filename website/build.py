#!/usr/bin/env python3
"""Generate the static greyd website into website/ for GitHub Pages.

This replaces the old PHP site. It renders the man pages from
doc/*.md into website/man/*.html and writes the site pages, all sharing
one header/footer template. Run it from anywhere:

    python3 website/build.py

The GitHub Pages workflow (.github/workflows/pages.yml) runs it and
publishes website/; the generated .html files are also committed so the
site can be served without the build step.
"""
import html
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOC = os.path.join(ROOT, "doc")
OUT = HERE

# The man pages, in navigation order, as (markdown base, section).
MAN_PAGES = [
    ("greyd", 8),
    ("greylogd", 8),
    ("greydb", 8),
    ("greyd-setup", 8),
    ("greyd-monitor", 8),
    ("greyd.conf", 5),
]

NAV = [("index.html", "home"), ("docs.html", "docs"),
       ("downloads.html", "downloads"), ("code.html", "code")]

YEAR = "2026"


def page(title, active, body, depth=0):
    """Wrap body in the shared header/footer. depth is how many
    directories deep the page is, for relative asset paths."""
    up = "../" * depth
    nav = []
    for href, key in NAV:
        cls = ' class="active"' if key == active else ""
        nav.append(f'<li{cls}><a href="{up}{href}">{key}</a></li>')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="greyd - a greylisting and blacklisting spam deferral daemon, a Go port of OpenBSD spamd.">
<link rel="stylesheet" href="{up}css/screen.css">
<script defer src="{up}js/site.js"></script>
</head>
<body>
<header class="group">
<h1 class="logo"><a href="{up}index.html">grey<span>d</span></a></h1>
<a class="menuControl expand" href="#">+</a>
<a class="menuControl collapse" href="#">-</a>
<nav><ul>{''.join(nav)}</ul></nav>
</header>
<main>
{body}
</main>
<footer>
<section><div class="content">
<p>Copyright &copy; 2014-{YEAR} Mikey Austin. greyd is free software under the ISC licence.
<a href="https://github.com/mikey-austin/greyd-v2">Source on GitHub</a>.</p>
</div></section>
</footer>
</body>
</html>
"""


def banner(text):
    return f'<section class="banner"><div class="content"><h2>{html.escape(text)}</h2></div></section>'


# --- man page rendering ------------------------------------------------------

def inline(text):
    """Render inline markdown to HTML (escaping first)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "`":
            j = text.find("`", i + 1)
            if j != -1:
                out.append("<code>" + html.escape(text[i + 1:j]) + "</code>")
                i = j + 1
                continue
        if text.startswith("**", i):
            j = text.find("**", i + 2)
            if j != -1:
                out.append("<strong>" + html.escape(text[i + 2:j]) + "</strong>")
                i = j + 2
                continue
        if c == "*":
            j = text.find("*", i + 1)
            if j != -1 and j > i + 1:
                out.append("<em>" + html.escape(text[i + 1:j]) + "</em>")
                i = j + 1
                continue
        # [text](url)
        m = re.match(r"\[([^\]]+)\]\(([^)]+)\)", text[i:])
        if m:
            out.append(f'<a href="{html.escape(m.group(2))}">{html.escape(m.group(1))}</a>')
            i += m.end()
            continue
        # [text][] or [text][ref] -> internal cross reference, drop the ref
        m = re.match(r"\[([^\]]+)\]\[[^\]]*\]", text[i:])
        if m:
            out.append(html.escape(m.group(1)))
            i += m.end()
            continue
        out.append(html.escape(c))
        i += 1
    return "".join(out)


def render_man(md):
    """Render a ronn-style man markdown string to an HTML fragment."""
    lines = md.split("\n")
    # Title: "name(section) -- summary" then a "====" underline.
    title_html = ""
    start = 0
    if len(lines) >= 2 and set(lines[1].strip()) == {"="}:
        m = re.match(r"(.+?)\((\d)\)\s*--\s*(.*)", lines[0])
        if m:
            title_html = (f"<h1>{html.escape(m.group(1))}({m.group(2)})</h1>"
                          f"<p class=\"tagline\">{html.escape(m.group(3))}</p>")
        else:
            title_html = f"<h1>{html.escape(lines[0])}</h1>"
        start = 2

    out = [title_html]
    i = start
    para = []

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
            i += 1
            continue
        if line.startswith("## "):
            flush()
            out.append("<h2>" + inline(line[3:].strip()) + "</h2>")
            i += 1
            continue
        if line.startswith("### "):
            flush()
            out.append("<h3>" + inline(line[4:].strip()) + "</h3>")
            i += 1
            continue
        # Indented code block: 4+ leading spaces (and not a list continuation).
        if line.startswith("    ") and not para:
            flush()
            block = []
            while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                if not lines[i].strip() and not block:
                    i += 1
                    continue
                block.append(lines[i][4:] if lines[i].startswith("    ") else "")
                i += 1
            while block and not block[-1].strip():
                block.pop()
            out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            continue
        # List: "* item", possibly with an indented continuation paragraph.
        if stripped.startswith("* "):
            flush()
            items = []
            while i < len(lines):
                s = lines[i].strip()
                if s.startswith("* "):
                    parts = [s[2:]]
                    i += 1
                    # gather indented continuation lines
                    while i < len(lines) and lines[i].startswith("  ") and lines[i].strip():
                        parts.append(lines[i].strip())
                        i += 1
                    items.append(" ".join(parts))
                elif not s:
                    # blank line: peek; end the list unless the next line is
                    # another bullet.
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and lines[j].strip().startswith("* "):
                        i = j
                        continue
                    break
                else:
                    break
            out.append("<ul>" + "".join("<li>" + inline(x) + "</li>" for x in items) + "</ul>")
            continue
        para.append(stripped)
        i += 1
    flush()
    return "\n".join(x for x in out if x)


def build_man():
    mandir = os.path.join(OUT, "man")
    os.makedirs(mandir, exist_ok=True)
    for base, section in MAN_PAGES:
        src = os.path.join(DOC, f"{base}.{section}.md")
        if not os.path.exists(src):
            print(f"warning: {src} missing, skipping", file=sys.stderr)
            continue
        frag = render_man(open(src, encoding="utf-8").read())
        body = f'<section><div class="content manpage">{frag}</div></section>'
        out = page(f"{base}({section}) - greyd", "docs", body, depth=1)
        with open(os.path.join(mandir, f"{base}.{section}.html"), "w", encoding="utf-8") as f:
            f.write(out)


# --- site pages --------------------------------------------------------------

def build_index():
    body = f"""
<section class="banner home"><div class="content">
<h2>Block spam before it sets foot in your network.</h2>
</div></section>
<section><div class="content group">
<div class="tile">
<h3>What is it?</h3>
<p><em>greyd</em> is a lightweight greylisting &amp; blacklisting daemon. It runs on your
gateway pretending to be a real mail server, tracks every host that connects and
automatically whitelists the ones that behave like real mail servers.</p>
<p><em>greyd</em> is written in <strong>Go</strong>, builds to static binaries with no C
dependencies, and drops privileges into a chroot with a per-process sandbox
(Landlock and seccomp on Linux, pledge on OpenBSD).</p>
<p>The suite is five programs:</p>
<ul>
<li><strong><a href="man/greyd.8.html">greyd</a></strong> &mdash; the main spam deferral daemon.</li>
<li><strong><a href="man/greylogd.8.html">greylogd</a></strong> &mdash; connection tracking &amp; whitelist updating.</li>
<li><strong><a href="man/greydb.8.html">greydb</a></strong> &mdash; greylisting / greytrapping database management.</li>
<li><strong><a href="man/greyd-setup.8.html">greyd-setup</a></strong> &mdash; blacklist &amp; whitelist population.</li>
<li><strong><a href="man/greyd-monitor.8.html">greyd-monitor</a></strong> &mdash; Prometheus metrics exporter.</li>
</ul>
</div>
<div class="tile">
<h3>Which systems are supported?</h3>
<p><em>greyd</em> runs on <strong>GNU/Linux</strong>, <strong>OpenBSD</strong>,
<strong>NetBSD</strong>, <strong>FreeBSD</strong> &amp; <strong>DragonFly BSD</strong>,
and they can all synchronise with each other.</p>
<p>It talks to the firewall through a pluggable driver:
<strong>netfilter</strong> (Linux, over netlink), <strong>pf</strong> (the BSDs),
<strong>ipfw</strong> (FreeBSD), <strong>npf</strong> (NetBSD) and a <strong>dummy</strong>
driver for setups where the firewall is managed elsewhere.</p>
<p>Greylisting state lives in a pluggable database:
<strong>sqlite</strong>, <strong>mysql</strong>, <strong>postgresql</strong>,
<strong>bolt</strong> (an embedded pure-Go store) or an in-memory store.</p>
<h3>Heritage</h3>
<p><em>greyd</em> follows the design of OpenBSD's excellent
<a href="https://man.openbsd.org/spamd">spamd</a>, implements its features and
synchronises with it over the same protocol. This is a faithful Go port of the
original C <em>greyd</em>, verified against spamd in continuous integration.</p>
</div>
<div class="tile">
<h3>Blacklisting</h3>
<p>Blacklists can be loaded into <em>greyd</em> with
<a href="man/greyd-setup.8.html">greyd-setup</a>. A host on a blacklist is answered
<em>very slowly</em>, byte by byte, to waste as much of the spammer's time as possible.</p>
<h3>Spam-trapping</h3>
<p><em>greyd</em> traps spammers (<em>greytrapping</em>) when they:</p>
<ul>
<li>send mail to a designated spamtrap address (set up with <a href="man/greydb.8.html">greydb</a>);</li>
<li>send mail to a backup MX out of order;</li>
<li>spoof a sender whose domain fails SPF validation.</li>
</ul>
<p>Trapped hosts are treated the same as blacklisted hosts.</p>
<h3>Observability</h3>
<p><a href="man/greyd-monitor.8.html">greyd-monitor</a> exports connection, greylist and
database metrics for Prometheus; <code>greyd --stats</code> prints the same counters and
<code>greydb -s</code> summarises the database.</p>
</div>
</div></section>
"""
    write("index.html", page("greyd - spam deferral daemon", "home", body))


def build_docs():
    items = "".join(
        f'<li><a href="man/{b}.{s}.html">{b}({s})</a></li>' for b, s in MAN_PAGES)
    body = banner("Documentation") + f"""
<section><div class="content group">
<div class="tile wide">
<h3>Manual pages</h3>
<ul>{items}</ul>
</div>
<div class="tile wide">
<h3>More</h3>
<ul>
<li><a href="https://github.com/mikey-austin/greyd-v2/blob/main/README.md">README</a></li>
<li><a href="https://github.com/mikey-austin/greyd-v2/blob/main/docs/ARCHITECTURE.md">Architecture</a> &mdash; the three processes, the ports &amp; adapters and the wire protocols</li>
<li><a href="https://github.com/mikey-austin/greyd-v2/blob/main/INSTALL">INSTALL</a> &mdash; building, packaging and systemd</li>
<li><a href="https://github.com/mikey-austin/greyd-v2/blob/main/NEWS">NEWS</a> &mdash; changes in this release</li>
</ul>
</div>
</div></section>
"""
    write("docs.html", page("Documentation - greyd", "docs", body))


def build_downloads():
    body = banner("Downloads") + """
<section><div class="content group">
<div class="tile wide">
<h3>Release binaries and packages</h3>
<p>Each release publishes static binaries for Linux, FreeBSD and OpenBSD (amd64 and
arm64), plus Debian and RPM packages, on the GitHub releases page. Archives ship with
signed checksums and an SBOM.</p>
<p><a href="https://github.com/mikey-austin/greyd-v2/releases/latest">Latest release &rarr;</a></p>
</div>
<div class="tile wide">
<h3>Install with Go</h3>
<p>With a Go 1.25 toolchain:</p>
<div class="highlight"><code>$ git clone https://github.com/mikey-austin/greyd-v2
$ cd greyd-v2
$ make
$ sudo make install</code></div>
<p>All firewall and database drivers and SPF support are compiled in; there are no
build-time feature flags. See <a href="https://github.com/mikey-austin/greyd-v2/blob/main/INSTALL">INSTALL</a>
for the paths, the system users and the systemd units.</p>
</div>
<div class="tile wide">
<h3>Packages</h3>
<p>Build Debian and RPM packages locally with:</p>
<div class="highlight"><code>$ make packages</code></div>
<p>They install the five programs, the sample configuration, the man pages and hardened
systemd units, and create the <code>greyd</code> and <code>greydb</code> system users.</p>
</div>
<div class="tile wide">
<h3>Docker</h3>
<p>A container image builds from the repository:</p>
<div class="highlight"><code>$ make docker</code></div>
</div>
</div></section>
"""
    write("downloads.html", page("Downloads - greyd", "downloads", body))


def build_code():
    body = banner("Code") + """
<section><div class="content group">
<div class="tile wide">
<h3>Grab a copy</h3>
<p>The code is on GitHub:
<a href="https://github.com/mikey-austin/greyd-v2">github.com/mikey-austin/greyd-v2</a>.</p>
<div class="highlight"><code>$ git clone https://github.com/mikey-austin/greyd-v2
$ cd greyd-v2
$ make          # build the five programs into bin/
$ make test     # go vet + unit tests
$ make lint     # golangci-lint + govulncheck</code></div>
<p>Building needs Go 1.25 and GNU make. Java is only needed for
<code>make generate</code>, which regenerates the ANTLR configuration parser; the
generated sources are committed.</p>
</div>
<div class="tile wide">
<h3>Layout</h3>
<p>The core (<code>internal/core</code>) defines the store, firewall and SPF ports; the
drivers live under <code>adapters/</code> and register themselves. The configuration
language is an ANTLR4 grammar, settings are a typed schema, and the programs are thin
wrappers under <code>internal/app</code> and <code>cmd</code>. See
<a href="https://github.com/mikey-austin/greyd-v2/blob/main/docs/ARCHITECTURE.md">docs/ARCHITECTURE.md</a>.</p>
</div>
<div class="tile wide">
<h3>Testing</h3>
<p>Beyond the unit, fuzz and property tests, the project runs end-to-end integration
harnesses in continuous integration: a privileged Linux container (netfilter, DNAT,
conntrack, NFLOG), and OpenBSD, FreeBSD, NetBSD and DragonFly BSD virtual machines
exercising pf, ipfw and npf. An OpenBSD job also verifies synchronisation against the
base-system spamd, and a nightly soak test watches for leaks.</p>
</div>
<div class="tile wide">
<h3>Contributing</h3>
<p>Issues and pull requests are welcome on GitHub. Please keep
<code>make test</code> and <code>make lint</code> green.</p>
</div>
</div></section>
"""
    write("code.html", page("Code - greyd", "code", body))


def write(name, content):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(content)
    print("wrote", name)


def main():
    build_man()
    build_index()
    build_docs()
    build_downloads()
    build_code()
    # Marker so GitHub Pages serves the tree verbatim (no Jekyll).
    open(os.path.join(OUT, ".nojekyll"), "w").close()


if __name__ == "__main__":
    main()
