#!/bin/sh
#
# greyd package post-removal script (deb postrm / rpm %postun).
#
# Called by dpkg as "postrm remove|purge|upgrade ..." and by rpm as
# "%postun 0" (erase) or "%postun 1" (upgrade). The pidfile directories
# are removed once the package is gone; the database directory
# /var/lib/greyd and the greyd/greydb users are deliberately kept, as the
# database is the administrator's data.

set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

case "${1:-}" in
    remove|purge|0)
        for d in /var/empty/greyd /var/empty/greylogd; do
            rm -f "$d/greyd.pid" "$d/greylogd.pid"
            rmdir "$d" >/dev/null 2>&1 || :
        done
        ;;
esac

exit 0
