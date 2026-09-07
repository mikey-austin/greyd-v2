#!/bin/sh
#
# greyd package pre-removal script (deb prerm / rpm %preun).
#
# Called by dpkg as "prerm remove" or "prerm upgrade new-version" and by
# rpm as "%preun 0" (erase) or "%preun 1" (upgrade). Running daemons are
# only stopped and disabled when the package is being removed, not on an
# upgrade (postinstall restarts them then).

set -e

case "${1:-}" in
    remove|0)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl --no-reload disable --now greyd-setup.timer >/dev/null 2>&1 || :
            systemctl --no-reload disable --now greyd.service greylogd.service >/dev/null 2>&1 || :
        fi
        ;;
esac

exit 0
