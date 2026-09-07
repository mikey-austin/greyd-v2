#!/bin/sh
#
# greyd package post-installation script (deb postinst / rpm %post).
#
# Called by dpkg as "postinst configure [previous-version]" and by rpm as
# "%post 1" (install) or "%post 2" (upgrade). Everything here is
# idempotent: users, groups and directories are only created when missing
# and existing ownership of populated directories is left alone.
#
# Users and directories match INSTALL ("Users and directories"):
#   greyd   main connection handling process, chrooted to /var/empty/greyd
#   greydb  greylister, greylogd and the database directory /var/lib/greyd

set -e

GREYD_USER=greyd
GREYDB_USER=greydb
GREYD_PIDDIR=/var/empty/greyd
GREYLOGD_PIDDIR=/var/empty/greylogd
DBDIR=/var/lib/greyd

add_group() {
    if ! getent group "$1" >/dev/null 2>&1; then
        groupadd -r "$1"
    fi
}

# add_user name group home comment
add_user() {
    if ! getent passwd "$1" >/dev/null 2>&1; then
        useradd -r -M -g "$2" -d "$3" -s /bin/false -c "$4" "$1"
    fi
}

# make_dir path owner group mode
make_dir() {
    if [ ! -d "$1" ]; then
        mkdir -p "$1"
        chown "$2:$3" "$1"
        chmod "$4" "$1"
    fi
}

add_group "$GREYD_USER"
add_group "$GREYDB_USER"
add_user "$GREYD_USER" "$GREYD_USER" "$GREYD_PIDDIR" "greyd daemon"
add_user "$GREYDB_USER" "$GREYDB_USER" "$DBDIR" "greyd database"

make_dir "$GREYD_PIDDIR" "$GREYD_USER" "$GREYD_USER" 0750
make_dir "$GREYLOGD_PIDDIR" "$GREYDB_USER" "$GREYDB_USER" 0750
make_dir "$DBDIR" "$GREYDB_USER" "$GREYDB_USER" 0750

# systemd: pick up the units; restart running daemons on upgrade. The
# units are not enabled automatically, see INSTALL ("systemd").
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    upgrade=0
    case "$1" in
        configure) [ -n "${2:-}" ] && upgrade=1 ;;
        [2-9]*) upgrade=1 ;;
    esac
    if [ "$upgrade" -eq 1 ]; then
        systemctl try-restart greyd.service greylogd.service >/dev/null 2>&1 || :
    fi
fi

exit 0
