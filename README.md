greyd - greylisting & blacklisting daemon
================================================

![Go CI](https://github.com/mikey-austin/greyd-golang/workflows/Go%20CI/badge.svg)

Project Website
---------------

Check out the project website (http://greyd.org) for more information and documentation.

Overview
--------

**greyd** is derived from OpenBSD's **spamd** spam deferral daemon and supporting programs.
As **spamd** is tightly integrated with the PF firewall, there are no production-ready
ports available for the GNU/Linux world. In addition to providing equivalent features
to **spamd**, **greyd** aims to:

  - Be firewall agnostic, and provide a generic interface for pluggable modules,
    to allow operation with *any* suitable firewall (eg iptables/ipset/netfilter, FreeBSD's
    IPFW, etc.). Currently **greyd** can transparently make use of **Netfilter** (via a
    pure Go netlink implementation) and **PF** with the *netfilter* and *pf* drivers; a
    *dummy* driver is available for testing and for setups where the firewall is managed
    elsewhere.

  - Provide a generic database interface for pluggable modules to work with a variety
    of different databases. The following drivers are available: *sqlite*, *mysql*,
    *postgresql*, *bolt* (an embedded key/value store which replaces Berkeley DB) and
    *memory* (non-persistent, for testing and containers).

  - Be portable and run on many different systems.

  - Have all of the programs in the **greyd** suite be driven by flexible configuration files,
    in addition to supporting the same command line switches as **spamd** & friends.

  - Have a clean & modularized internal structure, to facilitate unit & regression testing.

  - Be able to import the same blacklists & whitelists that **spamd** can import.

  - Be able to sync seemlessly with native **spamd**.

Building
--------

**greyd** is written in Go. Building requires:

  * Go 1.25 or later (go.mod pins the patched 1.25.x toolchain, which the go command
    downloads automatically; set GOTOOLCHAIN=local to build with the installed one)
  * GNU make
  * Java (only for `make generate`, which regenerates the ANTLR configuration
    parser after editing the grammar; the generated sources are committed)

All database and firewall drivers as well as SPF support are compiled into the
programs, so there are no build-time feature switches:

    $ make
    $ make test
    $ sudo make install

See the *INSTALL* file for the installation variables (`prefix`, `sysconfdir`,
`localstatedir`, `DESTDIR`, etc.) and the post-installation steps.

Docker
------

A multi-stage Dockerfile is provided in `packages/docker/Dockerfile`, which builds
**greyd** from source with the Go toolchain and produces a small alpine based runtime
image. Build it with:

    $ make docker

You can run greyd with something like:

    $ docker run -P -p8025:8025 --cap-add=NET_ADMIN mikeyaustin/greyd:go

Platforms
---------

Greyd runs on **GNU/Linux**, **OpenBSD**, **NetBSD**, **FreeBSD** & **DragonFly BSD**, and they can all sync to each other.

The greyd suite
-----------------

**greyd** provides analogous versions of each of the **spamd** programs, namely:

  * **greyd**       - the main spam deferral daemon
  * **greydb**      - greylisting/greytrapping database management
  * **greyd-setup** - blacklist & whitelist population
  * **greylogd**    - connection tracking & whitelist updating
  * **greyd-monitor** - Prometheus exporter for greyd's counters

Development Status
------------------

**greyd** is fully functional and is under active development. All of the features from **spamd**
have been implemented, including synchronization support. Additional features not found in **spamd** have also been implemented, such as **SPF** trapping & optional whitelisting, sync support via greydb and fast blacklist lookup via an internal radix trie.

**greyd** is now fully sync compatible with **spamd**, which would allow, for example, an administrator to add a **greyd** instance into a cluster of existing **spamd** instances.

The following database drivers have been implemented:
  * **SQLite 3** (embedded, pure Go)
  * **MySQL**
  * **PostgreSQL**
  * **bolt**, an embedded pure Go key/value store which replaces the Berkeley DB drivers of earlier releases
  * **memory**, a non-persistent in-process store for testing and ephemeral deployments

For GNU/Linux, a firewall driver has been implemented for the netfilter ecosystem. This driver talks to the kernel directly over netlink and makes use of:
  * **ipset** for IP set management
  * **NFLOG** for the tracking and auto-whitelisting of connections
  * **conntrack** for the DNAT original destination lookups

For the BSDs, a **PF** firewall driver has been implemented. A **dummy** firewall driver is also available.

### Status of the Go port

The current code base is a port to Go of the original C implementation. It keeps the same
programs, configuration files, command line switches, wire protocols and sync protocol, so it
is a drop-in replacement. The process model, the pipes between the processes and the
ports & adapters layout of the code are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
The following points remain to be done:
  * the **netfilter** and **pf** firewall drivers have been ported but still need verification
    on real hosts (the port was developed without root access to a suitable kernel)
  * the **npf** (NetBSD) firewall driver has not yet been ported; on NetBSD the **pf** driver
    falls back to the proxy address for original destination lookups
  * the **sqlite** driver is not available on DragonFly BSD (the embedded SQLite has no port
    for it); use **bolt** there
  * more testing in the wild on different setups

The port fixes a few defects of the C implementation on purpose, so behaviour differs in
these corners:

  * `hostname` set in **greyd.conf** is honoured (the C daemon always used the system host name
    unless **-h** was given)
  * `low_prio_mx` is read from the *grey* section as documented (and the **-M** switch works);
    a value in the default section is still accepted
  * when the proxy protocol is enabled, blacklists are matched against the real client address
    from the PROXY header rather than the load balancer's address
  * the greylister does not whitelist a retried tuple whose address already has a whitelist
    entry, for every database driver (the SQL drivers already behaved this way)
  * a malformed message on an internal pipe or the configuration socket is logged and skipped
    instead of terminating the process

The port also adds a few hardening options, all off or generous by default so existing
configurations behave as before: `config_socket` (a unix domain socket for **greyd-setup**
checked against the peer's credentials), `max_config_frame`, `max_cons_per_source`,
`max_line_length`, `max_domains`, `max_entries` and the sync `replay_window`, plus `sandbox`
(on by default: Landlock, seccomp and no-new-privs on Linux, pledge on OpenBSD, applied by each
process after it drops privileges). `greyd -t`
checks a configuration file, `greyd --drivers` lists the compiled-in drivers and `greyd --stats`
prints the running daemon's counters (also served to Prometheus by **greyd-monitor**(8) and
summarised by `greydb -s`). The PROXY protocol handler accepts version 1 and version 2 headers.
On Linux, `greyd` can also be started without root through the installed socket units
(`greyd.socket`, `greyd-config.socket`, `greyd-unprivileged.service`). See **greyd.conf**(5) and
**greyd**(8).

Licensing
---------

All of the source is licensed under the OpenBSD (ISC) license, with the exception of the netfilter
firewall adapter, which remains licensed under the GPL as it was before the port. All drivers are
now compiled into the programs; the licensing of the netfilter adapter is unchanged by this.
