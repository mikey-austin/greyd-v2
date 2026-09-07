greyd.conf(5) -- greyd configuration file
=========================================

## SYNOPSIS

This configuration file is read by **greyd**, **greydb**, **greylogd** and **greyd-setup**.

## DESCRIPTION

The syntax consists of sequences of assignments, each terminated by a newline:

    # A string value.
    variable = "value"

    # A number value.
    variable = 10  # Another comment.

    # A list value may contain strings or numbers.
    # Trailing commas are allowed.
    variable = [ 10, "value", ]

Comments, whitespace and blank lines are ignored.

*Sections* may contain many assignments, separated by a newline.

    section sectionname {
        var1 = "val1"
        var2 = 10
        var3 = [ 1, 2, 3 ]
    }

*Blacklists* and *whitelists* use the same syntax as the *section* above (see [BLACKLIST CONFIGURATION][]):

    blacklist blacklistname {
        ...
    }

    whitelist whitelistname {
        ...
    }

Configuration may also be recursively loaded by way of an *include*:

    # Globbing is supported.
    include "/etc/greyd/conf.d/*.conf"

## GENERAL OPTIONS

The following options may be specified outside of a section. A *boolean* value is a *number* which takes the values *0* or *1*.

* **syslog_enable** = *boolean*:
  Send log messages to **syslogd**(8) (facility daemon). Enabled by default; the tools force it off, and *log_to_file* can be used with or without it.

* **debug** = *boolean*:
  Log debug messages which are suppressed by default.

* **verbose** = *boolean*:
  Log blacklisted connection headers.

* **log_to_file** = *string*:
  When this option is set greyd will send logs to the specified path. This is useful for
  containerized environments.

* **daemonize** = *boolean*:
  Detach from the controlling terminal. Defaults to *1*.

* **proxy_protocol_enable** = *boolean*:
  Proxy protocol configuration. Enabling this configuration allows greyd to sit behind a TCP load balancer that speaks the proxy protocol as defined in the [protocol spec](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).
  Both version 1 (text) and version 2 (binary) headers are accepted; the version is detected from the first bytes of the connection. Version 2 *LOCAL* commands (as sent by health checks) are honoured, in which case the connection's own addresses are used, and any TLVs are skipped. Headers for unsupported address families (UNSPEC, UDP and unix sockets), like a version 1 *UNKNOWN* header, are refused.
  Defaults to *false*. Note that if this is enabled *all* client connections will need to specify the proxy protocol header first, ie there is no mixing of proxied and direct requests.
  You *must* also specify the `proxy_protocol_permitted_proxies` list of trusted proxies. There are many upstream proxies/load balancers that support this protocol, for example nginx and haproxy to name a couple.

* **proxy_protocol_permitted_proxies** = *list*:
  The upstream proxies must be explicitly configured. Without this any client would be able to spoof their addresses. This setting
  only has an effect if `proxy_protocol_enable` is set to *true*. The elements in this list must be strings consisting of IPv4 and/or IPv6
  CIDRs.

* **drop_privs** = *boolean*:
  Drop priviliges and run as the specified **user**. Defaults to *1*.

* **chroot** = *boolean*:
  Chroot the main **greyd** process that accepts connections. Defaults to *1*.

* **chroot_dir** = *string*:
  The location to chroot to.

* **sandbox** = *boolean*:
  Confine each process once it has dropped privileges and opened what it needs. On Linux this sets *no_new_privs*, restricts filesystem access with Landlock (the main and firewall processes keep none, the greylister keeps its database directory and */etc* for the resolver) and installs a seccomp filter that refuses to start programs, trace, mount, load modules or change namespaces. On OpenBSD the processes are pledged. Unsupported kernels are skipped with a debug message. Enabled by default; set to *0* when running a database or firewall driver with unusual filesystem needs.

* **sandbox_strict** = *boolean*:
  On Linux, replace the sandbox's seccomp deny list with an allow list of the system calls the Go runtime and the drivers are known to use; anything else fails with EPERM and is logged by the affected operation rather than killing the process. Tighter, but a database driver or kernel needing an unlisted call will surface as errors, so try it in a test environment first. Off by default.

* **setrlimit** = *boolean*:
  Use setrlimit to self-impose resource limits such as the maximum number of file descriptors (ie connections).

* **max_cons** = *number*:
  The maximum number of concurrent connections to handle. This number can not exceed the operating system maximum file descriptor limit. Defaults to *800*.

* **max_cons_black** = *number*:
  The maximum number of concurrent blacklisted connections to tarpit. This number can not exceed the maximum configured number of connections. Defaults to *800*.

* **port** = *number*:
  The port to listen on. Defaults to *8025*.

* **user** = *string*:
  The username for the main **greyd** daemon the run as.

* **bind_address** = *string*:
  The IPv4 address to listen on. Defaults to listen on all addresses.

* **port** = *number*:
  The port to listen on. Defaults to *8025*.

* **config_port** = *number*:
  The port on which to listen for blacklist configuration data (see **greyd-setup**(8)). Defaults to *8026*.

* **config_socket** = *string*:
  When set, blacklist configuration data is accepted on this unix domain socket instead of the loopback TCP port. Only the super user and the *user* **greyd** runs as may connect (the peer credentials are checked). **greyd-setup**(8) reads the same option to find the daemon. Unset by default.

* **max_config_frame** = *number*:
  The largest blacklist (in bytes) accepted on a configuration connection or from the greylister. Defaults to *67108864* (64 MiB); the minimum is *1024*.

* **max_cons_per_source** = *number*:
  The maximum number of simultaneous connections accepted from one client address; further connections from that address are closed immediately. *0* (the default) disables the limit.

* **max_line_length** = *number*:
  The longest SMTP command line (in bytes) a client may send before the line is rejected with a 500 error. Defaults to *8191*.

* **greyd_pidfile** = *string*:
  The greyd pidfile path.

* **greylogd_pidfile** = *string*:
  The greylogd pidfile path.

* **hostname** = *string*:
  The hostname to display to clients in the initial SMTP banner.

* **enable_ipv6** = *boolean*:
  Listen for IPv6 connections. Disabled by default.

* **bind_address_ipv6** = *string*:
  The IPv6 address to listen on. Only has an effect if **enable_ipv6** is set to true.

* **stutter** = *number*:
  For blacklisted connections, the number of seconds between stuttered bytes.

* **window** = *number*:
  Adjust the socket receive buffer to the specified number of bytes (window size). This slows down spammers even more.

* **banner** = *string*:
  The banner message to be displayed to new connections.

* **error_code** = *string*:
  The SMTP error code to show blacklisted spammers. May be either *"450"* (default) or *"550"*.

## FIREWALL SECTION

The following options are common to all firewall drivers:

* **driver** = *string*:
  The name of the firewall driver to use. All drivers are compiled into the programs and are selected by name. May be one of *netfilter*, *pf*, *ipfw*, *npf* or *dummy*. Legacy values from previous releases such as *"/usr/lib/greyd/greyd_netfilter.so"* or *"greyd_netfilter.la"* are still accepted: the basename is used and the *greyd_* prefix and *.so*/*.la* suffix are ignored. For example:

        section firewall {
            #driver = "pf"
            #driver = "dummy"
            driver = "netfilter"

            # Driver-specific options below.
            ...
        }

### Netfilter firewall driver

This driver runs on GNU/Linux systems and talks to the kernel directly over netlink, making use of *ipset* for set management, *conntrack* for original destination lookups and *NFLOG* for connection tracking. The process holding the firewall handle needs the *CAP_NET_ADMIN* capability, which **greyd** retains when dropping privileges.

* **max_elements** = *number*:
  Maximum number of ipset elements. Defaults to *200,000*.

* **hash_size** = *number*:
  Maximum ipset hash size for each set.

* **track_outbound** = *boolean*:
  Track outbound connections. See **greylogd**(8) for more details.

### NPF firewall driver

This driver runs on NetBSD with the NPF firewall. Whitelists are kept in NPF tables declared in *npf.conf* as dynamic tables (*table <greyd-whitelist> type ipset*) and replaced in one step with *npfctl table ... replace*; connections are tracked by reading the *npflog0* interface with *bpf* (its records have the *pflog* layout). NPF offers no public lookup of a redirected connection's original destination, so the address the connection arrived on is used; the low priority MX trap therefore only works for connections that are not redirected. *npfctl* needs the NPF device, so the process holding this driver keeps its privileges.

* **npfctl_path** = *string*:
  Path to the npfctl utility, defaults to */sbin/npfctl*.

* **npflog_if** = *string*:
  The npflog interface to read logged packets from, defaults to *npflog0* (create it with *ifconfig npflog0 create* and log rules with *apply "log"* in *npf.conf*).

* **net_if** = *string*:
  As for the pf driver.

* **track_outbound** = *boolean*:
  Track outbound connections. See **greylogd**(8) for more details.

* **inbound_group** = *number*:
  The *--nflog-group* to indicate inbound SMTP connections.

* **outbound_group** = *number*:
  The *--nflog-group* to indicate outbound SMTP connections.

### PF firewall driver

This driver runs on BSD systems making use of the PF firewall. Tables are replaced through *pfctl*, logged packets are read directly from the *bpf* device attached to the *pflog* interface, and original destination lookups use the *DIOCNATLOOK* ioctl (OpenBSD, FreeBSD and DragonFly BSD; on NetBSD the proxy address is returned).

* **pfdev_path** = *string*:
  Path to pfdev, defaults to */dev/pf*.

* **pfctl_path** = *string*:
  Path to pfctl utility, defaults to */sbin/pfctl*.

* **pflog_if** = *string*:
  Pflog interface to listen for logged packets, defaults to *pflog0*.

### IPFW firewall driver

This driver runs on FreeBSD with the *ipfw* firewall. Whitelists are kept in ipfw lookup tables (*type addr*, holding IPv4 and IPv6 prefixes) which are replaced atomically: the entries are loaded into a staging table named after the set with *_new* appended and swapped into place with *ipfw table swap*. Connections are tracked by reading the *ipfw0* log interface with *bpf*; the original destination of a redirected connection is the address the connection arrived on, since *ipfw fwd* delivers the packet to the local socket without rewriting it. The ipfw control socket checks privileges on every operation, so the process holding this driver keeps them (see [PRIVILEGE SEPARATION AND SANDBOXING][] in **greyd**(8)).

* **ipfw_path** = *string*:
  Path to the ipfw utility, defaults to */sbin/ipfw*.

* **ipfw_log_if** = *string*:
  The ipfw log interface to read logged packets from, defaults to *ipfw0*. Create it with *ifconfig ipfw0 create* and set *net.inet.ip.fw.verbose* to *0* so that logged packets go to the interface rather than to syslog.

* **net_if** = *string*:
  When set, only the addresses of this interface count as local when deciding whether a logged SMTP connection is inbound (whitelist its source) or outbound (whitelist its destination). Defaults to all interfaces.

* **track_outbound** = *boolean*:
  Track outbound connections. See **greylogd**(8) for more details.

* **net_if** = *string*:
  Network interface to restrict monitored logged packets to. Not set by default.

## DATABASE SECTION

The following options are common to all database drivers:

* **driver** = *string*:
  The name of the database driver to use. All drivers are compiled into the programs and are selected by name. May be one of *sqlite*, *mysql*, *postgresql*, *bolt* or *memory*. Legacy values from previous releases such as *"/usr/lib/greyd/greyd_sqlite.so"* or *"greyd_sqlite.la"* are still accepted: the basename is used, the *greyd_* prefix and *.so*/*.la* suffix are ignored, and the former *bdb* and *bdb_sql* drivers map to *bolt*. For example:

        section database {
            driver = "bolt"
            #driver = "sqlite"
            #driver = "mysql"
            #driver = "postgresql"
            #driver = "memory"

            # Driver-specific options below.
            ...
        }

### Bolt database driver

The bolt driver is an embedded, transactional key/value store (bbolt) written in pure Go, which replaces the Berkeley DB drivers of previous releases. It needs no external libraries or services. Note that existing Berkeley DB database files are not readable by this driver; as the database only holds short-lived greylisting state, it is simply rebuilt.

* **path** = *string*:
  The filesystem path to the directory containing the database file. Defaults to */var/db/greyd*.

* **db_name** = *string*:
  The name of the database file, relative to the specified **path**. Defaults to *greyd.db*.

### SQLite database driver

The SQLite database driver uses an embedded SQLite implementation. No special initialization is required as the driver will manage the schema internally.

* **path** = *string*:
  The filesystem path to the directory containing the database files. Defaults to */var/db/greyd*.

* **db_name** = *string*:
  The name of the database file, relative to the specified **path**. Defaults to *greyd.sqlite*.

### MySQL database driver

The MySQL driver connects to a MySQL (or MariaDB) server. The schema is created automatically on first use; it is also shipped as **mysql_schema.sql** with the source distribution for those who prefer to create it by hand.

* **host** = *string*:
  The database host. Defaults to *localhost*.

* **port** = *number*:
  The database port. Defaults to 3306.

* **name** = *string*:
  The database name. Defaults to *greyd*.

* **user** = *string*:
  The database username.

* **pass** = *string*:
  The database password.

* **socket** = *string*:
  The path to the UNIX domain socket.

### PostgreSQL database driver

The PostgreSQL driver connects to a PostgreSQL server. The schema is created automatically on first use; it is also shipped as **postgresql_schema.sql** with the source distribution for those who prefer to create it by hand.

* **host** = *string*:
  The database host. Defaults to *localhost*.

* **port** = *number*:
  The database port. Defaults to 5432.

* **name** = *string*:
  The database name. Defaults to *greyd*.

* **user** = *string*:
  The database username.

* **pass** = *string*:
  The database password.

* **socket** = *string*:
  The path to the UNIX domain socket.

### Memory database driver

The memory driver keeps the database in the memory of the greylisting process. Nothing is persisted, so all state is lost when the process exits. It is intended for testing and for ephemeral container deployments.

* **name** = *string*:
  The name identifying the in-process database. Defaults to *default*.

## GREY SECTION

* **enable** = *boolean*:
  Enable/disable the greylisting engine. Defaults to *1*.

* **user** = *string*:
  The username to run as for the greylisting processes. Defaults to *greydb*. This should differ from the *user* that the main **greyd** process is running as.

* **traplist_name** = *string*:
  The name of the blacklist to which spamtrapped hosts are added.

* **traplist_message** = *string*:
  The blacklist rejection message. See the *message* field in [BLACKLIST CONFIGURATION][].

* **whitelist_name** = *string*:
  The firewall whitelist *set/table* name. Defaults to *greyd-whitelist*.

* **whitelist_name_ipv6** = *string*:
  The firewall whitelist *set/table* name for IPv6 hosts. Defaults to *greyd-whitelist-ipv6*.

* **low_prio_mx** = *string*:
  The address of the secondary MX server, to greytrap hosts attempting to deliver spam to the MX servers in the incorrect order.

* **stutter** = *number*:
  Kill stutter for new grey connections after so many seconds. Defaults to *10*.

* **permitted_domains** = *string*:
  Filesystem location of the domains allowed to receive mail. If this file is specified (and exists), any message received with a RCPT TO domain *not* matching an entry in the below file will be greytrapped (ie blacklisted).

* **db_permitted_domains** = *boolean*:
  Augment *permitted_domains* (or replace if *permitted_domains* is not set) with DOMAIN entries loaded into the database. See **greydb**(8) for more on managing these database permitted domains.

* **pass_time** = *number*:
  The amount of time in seconds after which to whitelist grey entries. Defaults to *25 minutes*.

* **grey_expiry** = *number*:
  The amount of time in seconds after which to remove grey entries. Defaults to *4 hours*.

* **white_expiry** = *number*:
  The amount of time in seconds after which to remove whitelisted entries. Defaults to *31 days*.

* **trap_expiry** = *number*:
  The amount of time in seconds after which to remove greytrapped entries. Defaults to *1 day*.

* **max_domains** = *number*:
  The maximum number of entries read from the *permitted_domains* file; a longer file is truncated with a warning. Defaults to *100000*, *0* disables the limit.

## SYNCHRONISATION SECTION

* **enable** = *boolean*:
  Enable/disable the synchronisation engine. Defaults to *0*.

* **hosts** = *list*:
  Specify a list of *sync targets*. See the **-Y** option in **greyd**(8).

* **bind_address** = *string*:
  See **-y** option in **greyd**(8).

* **port** = *number*:
  The port on which to listen for incoming UDP sync messages.

* **ttl** = *number*:
  Specify a multicast TTL value. Defaults to *1*.

* **verify** = *boolean*:
  Load the specified *key* for verifying sync messages.

* **key** = *string*:
  The filesystem path to the key used to verify sync messages.

* **mcast_address** = *string*:
  The multicast group address for sync messages.

* **replay_window** = *number*:
  Sync messages carry a counter; a message whose counter has already been seen from the same peer within the last *replay_window* counters is dropped, which defeats replayed captures. Defaults to *64*, *0* disables the check (needed when peers do not use monotonic counters). State is kept for at most 1024 peers; beyond that the least recently heard peer is forgotten.

## SPF SECTION

This section controls the operation of the SPF validation functionality. SPF support is always built in.

* **enable** = *boolean*:
  Enable the SPF checking functionality.

* **trap_on_softfail** = *boolean*:
  Trap a host producing an SPF softfail. SPF hardfails are always trapped.

* **whitelist_on_pass** = *boolean*:
  Whitelist a host which passes SPF validation. This is disabled by default.

## MONITOR SECTION

This section controls **greyd-monitor**(8), the Prometheus exporter.

* **bind_address** = *string*:
  The address to serve metrics on. Defaults to *127.0.0.1*; set it to an interface address to let a remote Prometheus scrape it.

* **port** = *number*:
  The metrics port. Defaults to *9143*.

* **interval** = *number*:
  How often, in seconds, **greyd-monitor** polls **greyd** for its counters. Defaults to *30*.

* **user** = *string*:
  The user **greyd-monitor** drops to when started as root. Defaults to the main *user*, which the configuration socket admits.

## SETUP SECTION

This section controls the operation of the **greyd-setup**(8) program.

* **lists** = *list*:
  The list of blacklists/whitelists to load. The order is important, see [BLACKLIST CONFIGURATION][]. Consecutive blacklists will be merged, with overlapping regions removed. If a blacklist (or series of blacklists) is followed by a whitelist, any address appearing on both will be removed.

* **curl_path** = *string*:
  The path to the *curl* program, which is used to fetch the lists via *HTTP* and *FTP*.

* **max_entries** = *number*:
  The maximum number of addresses read from a single list; the remainder is dropped with a warning. Defaults to *10000000*.

* **curl_proxy** = *string*:
  Specify a *proxyhost[:port]* through which to fetch the lists.

## BLACKLIST CONFIGURATION

A blacklist must contain the following fields:

* **message** = *string*:
  The message to be sent to **greyd**(8). This message will be displayed to clients who are on this list.

* **method** = *string*:
  The method in which the list of addresses is fetched. This may be one of *https*, *http*, *ftps*, *ftp*, *exec* or *file*. Prefer *https* (or *ftps*): the fetched list is trusted and loaded verbatim into the live blacklist, so a plaintext transport lets a network attacker or a compromised mirror inject arbitrary addresses. Downloads are restricted to the named scheme (redirects are not followed), time limited and size limited.

* **file** = *string*:
  The argument to the specified *method*. For example, if the *http* method is specified, the *file* refers to the URL (minus the protocol).

An example blacklist definition is as follows:

    blacklist nixspam {
        message = "Your address %A is in the nixspam list"
        method  = "https"
        file = "www.openbsd.org/spamd/nixspam.gz"
    }

### Whitelist definitions

Whitelist definitions take the same fields as a blacklist definition, with the exception of the *message* (which is not applicable). For example:

    whitelist work_clients {
        method = "exec"
        file = "cat /tmp/work-clients-traplist.gz"
    }

### Address format

The format of the list of addresses is expected to consist of one network block or address per line (optionally followed by a space and text that is ignored). Comment lines beginning with # are ignored. Network blocks may be specified in any of the formats as in the following example:

    # CIDR format
    192.168.20.0/24
    # A start - end range
    192.168.21.0 - 192.168.21.255
    # As a single IP address
    192.168.23.1

Note, currently only IPv4 addresses are supported.

## COPYRIGHT

**greyd** is Copyright (C) 2015 Mikey Austin (greyd.org)

## SEE ALSO

  **greyd**(8), **greyd-setup**(8), **greydb**(8), **greylogd**(8)
