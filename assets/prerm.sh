#!/bin/sh
# Modified from https://github.com/caddyserver/dist/blob/master/scripts/preremove.sh
# Apache License 2.0

set -e

if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
	deb-systemd-invoke stop ayano.service >/dev/null || true
fi
