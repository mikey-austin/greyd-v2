# Configuration compatibility corpus

Every file in this directory is parsed with `parse.String` and loaded with
`settings.Load` by `corpus_test.go` in the parent package. Loading must
succeed and must produce no warnings, except for the per-file allowances
listed in `expectedWarnings` in the test.

`parse.String` records `include` directives without resolving them, so
files carrying includes (the shipped samples comment theirs out) never
touch the filesystem.

## Origins

| File | Origin |
|------|--------|
| `c-etc-greyd.conf` | `etc/greyd.conf.in` of the C reference tree (`/home/mikey/Workspace/greyd`), autoconf placeholders substituted |
| `c-etc-greyd.docker.conf` | `etc/greyd.docker.conf.in` of the C reference tree, placeholders substituted |
| `go-etc-greyd.conf` | this repository's `etc/greyd.conf.in`, placeholders substituted |
| `go-etc-greyd.docker.conf` | this repository's `etc/greyd.docker.conf.in`, placeholders substituted |
| `doc-conf5-syntax.conf` | `doc/greyd.conf.5.md`, DESCRIPTION, assignment syntax examples (`variable` is not an option; the test expects the warning) |
| `doc-conf5-section.conf` | `doc/greyd.conf.5.md`, DESCRIPTION, section syntax example |
| `doc-conf5-lists.conf` | `doc/greyd.conf.5.md`, DESCRIPTION, blacklist/whitelist skeletons with the `...` bodies filled in |
| `doc-conf5-include.conf` | `doc/greyd.conf.5.md`, DESCRIPTION, include example |
| `doc-conf5-firewall.conf` | `doc/greyd.conf.5.md`, FIREWALL SECTION, driver example (`...` removed) |
| `doc-conf5-firewall-drivers.conf` | every option documented under FIREWALL SECTION, assembled into one section |
| `doc-conf5-database.conf` | `doc/greyd.conf.5.md`, DATABASE SECTION, driver example (`...` removed) |
| `doc-conf5-database-drivers.conf` | every option documented under DATABASE SECTION, assembled into one section |
| `doc-conf5-blacklist.conf` | `doc/greyd.conf.5.md`, BLACKLIST CONFIGURATION, example blacklist and whitelist |
| `doc-greyd8-greytrapping.conf` | `doc/greyd.8.md`, GREYTRAPPING, grey section fragment (`...` removed) |
| `doc-greyd8-sync.conf` | `doc/greyd.8.md`, SYNCHRONISATION, sync section fragment (`...` removed) |
| `legacy-low-prio-mx.conf` | hand written: `low_prio_mx` in the default section as the C code read it (the test expects the placement warning) |
| `legacy-driver-paths.conf` | hand written: shared object driver paths of a C installation |

The placeholder values used for the `.in` templates, following the
`configure.ac` defaults of the C tree with `prefix=/usr`:

| Placeholder | Value |
|-------------|-------|
| `@libdir@` | `/usr/lib` |
| `@PACKAGE@` | `greyd` |
| `@localstatedir@` | `/var` |
| `@sysconfdir@` | `/etc` |
| `@CURL@` | `/usr/bin/curl` |
| `@GREYD_PIDFILE@` | `/var/empty/greyd/greyd.pid` |
| `@GREYLOGD_PIDFILE@` | `/var/empty/greylogd/greylogd.pid` |

Not included: the `check/data/*.conf.in` files of the C tree are parser
unit test inputs with made-up option names and circular includes, not
greyd configurations; this repository already carries copies under
`internal/config/parse/testdata`. The other indented blocks of the manual
pages are shell commands, iptables rules, an rsyslog rule, an address list
and a configuration socket frame, none of which is a configuration file.
