#!/bin/sh
# Modified from https://github.com/caddyserver/dist/blob/master/scripts/postremove.sh
# Apache License 2.0

set -e

if [ -d /run/systemd/system ]; then
	systemctl --system daemon-reload >/dev/null || true
fi

if [ "$1" = "remove" ]; then
	if [ -x "/usr/bin/deb-systemd-helper" ]; then
		deb-systemd-helper mask ayano.service >/dev/null || true
	fi
fi

if [ "$1" = "purge" ]; then
	if [ -x "/usr/bin/deb-systemd-helper" ]; then
		deb-systemd-helper purge ayano.service >/dev/null || true
		deb-systemd-helper unmask ayano.service >/dev/null || true
	fi
	# 'purge' is not supposed to leave package files behind,
	# so remove the user along with other dirs.
	userdel -r ayano || true
	rm -rf /var/log/ayano
fi
