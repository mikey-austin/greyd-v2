greyd-monitor(8) -- Prometheus exporter for greyd
=================================================

## SYNOPSIS

`greyd-monitor` [**-dFV**] [**-f** config] [**-l** address] [**-p** port] [**-i** seconds]

## DESCRIPTION

**greyd-monitor** polls a running **greyd**(8) for its operational counters and serves them in the Prometheus text exposition format, so that greylisting activity, connection load, blacklist sizes and database growth can be graphed and alerted on.

It asks **greyd** for its statistics over the configuration socket (see [CONFIGURATION CONNECTIONS][] in **greyd**(8)) every *interval* seconds and keeps the last answer. Scrapes are served from memory, so a slow or unresponsive **greyd** never slows down the scraper; **greyd_up** reports whether the last poll succeeded.

The options are as follows:

* **-f** *config*:
  The main greyd configuration file. The *monitor* section and the *config_socket* / *config_port* variables are read from it; see **greyd.conf**(5).

* **-l** *address*:
  The address to serve metrics on (overrides *monitor.bind_address*, default *127.0.0.1*).

* **-p** *port*:
  The port to serve metrics on (overrides *monitor.port*, default *9143*).

* **-i** *seconds*:
  How often to poll **greyd** (overrides *monitor.interval*, default *30*).

* **-d**:
  Debugging mode. **greyd-monitor** displays debug messages (suppressed by default).

* **-F**:
  Run in the foreground instead of detaching (the *daemonize* option).

* **-V**:
  Print the version and exit.

## ENDPOINTS

* */metrics*:
  The metrics, in the Prometheus text format.

* */healthz*:
  Returns *200* when the last poll of **greyd** succeeded and *503* otherwise, for load balancer or container health checks.

## METRICS

All metrics are prefixed **greyd_**. Counters are cumulative since **greyd** started; gauges are instantaneous. Database entry gauges are taken from the greylister's periodic database scan and are omitted until the first scan has completed.

* **greyd_up**:
  1 when the last poll succeeded.

* **greyd_uptime_seconds**:
  Seconds since **greyd** started.

* **greyd_greylisting_enabled**:
  0 when **greyd** runs in blacklist-only mode.

* **greyd_connections{state="all"|"black"}**, **greyd_max_connections{state=...}**:
  Currently open SMTP connections, and the configured limits (*max_cons*, *max_cons_black*).

* **greyd_connections_total{result="accepted"|"accepted_black"|"refused_full"|"refused_source"}**:
  Connections accepted (and how many of those were blacklisted on arrival), and connections closed on accept because the global or the per-source limit was reached.

* **greyd_greylist_tuples_total**:
  Envelopes (client, HELO, sender, recipient) handed to the greylister.

* **greyd_replies_total{kind="grey"|"black"}**:
  Final rejections sent: the temporary failure to greylisted clients, or a blacklist message.

* **greyd_proxy_headers_total**:
  Accepted PROXY protocol headers.

* **greyd_db_entries{type="grey"|"white"|"trapped"|"spamtrap"|"domain"}**, **greyd_db_scan_age_seconds**:
  Database entries by kind at the last scan, and how long ago that scan ran.

* **greyd_blacklist_entries{name=...}**:
  Entries in each blacklist loaded through **greyd-setup**(8) or the greytrap.

* **greyd_monitor_polls_total{result="ok"|"error"}**, **greyd_monitor_poll_duration_seconds**, **greyd_monitor_last_poll_timestamp_seconds**, **greyd_monitor_build_info{version=...}**:
  The exporter's own health.

## PRIVILEGES

**greyd-monitor** needs no privileges other than access to the configuration socket. With *config_socket* set, **greyd** admits the super user and the user it runs as (the *user* option), so run **greyd-monitor** as that user; when started as root it drops to *monitor.user*, or to *user* when that is unset. With the loopback TCP configuration port, **greyd** requires a reserved source port and **greyd-monitor** must then run as root, so *config_socket* is recommended. Each process confines itself after start up when the *sandbox* option is on.

A scrape configuration for Prometheus:

    scrape_configs:
      - job_name: greyd
        static_configs:
          - targets: ['mx.example.org:9143']

The same counters can be printed on the command line with **greyd --stats**, and the database counts alone with **greydb -s**.

## COPYRIGHT

**greyd-monitor** is Copyright (C) 2014-2026 Mikey Austin (greyd.org). All rights reserved.

## SEE ALSO

  greyd.conf(5), greyd(8), greydb(8), greyd-setup(8), greylogd(8)

## CREDITS

  * Mikey Austin
