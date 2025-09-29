#!/bin/sh
# Modified from https://github.com/caddyserver/dist/blob/master/scripts/postinstall.sh
# Apache License 2.0

set -e

if [ "$1" = "configure" ]; then
	# Add user
	if ! getent passwd ayano >/dev/null; then
		useradd --system \
			--create-home \
			--shell /usr/sbin/nologin \
			--comment "Ayano" \
			ayano
	fi
	if getent group adm >/dev/null; then
		usermod -aG adm ayano
	fi

	# Add log directory with correct permissions
	if [ ! -d /var/log/ayano ]; then
		mkdir -p /var/log/ayano
		chown -R ayano:nogroup /var/log/ayano
	fi
fi

if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	# This will only remove masks created by d-s-h on package removal.
	deb-systemd-helper unmask ayano.service >/dev/null || true

	# was-enabled defaults to true, so new installations run enable.
	if deb-systemd-helper --quiet was-enabled ayano.service; then
		# Enables the unit on first installation, creates new
		# symlinks on upgrades if the unit file has changed.
		deb-systemd-helper enable ayano.service >/dev/null || true
		deb-systemd-invoke start ayano.service >/dev/null || true
	else
		# Update the statefile to add new symlinks (if any), which need to be
		# cleaned up on purge. Also remove old symlinks.
		deb-systemd-helper update-state ayano.service >/dev/null || true
	fi

	# Restart only if it was already started
	if [ -d /run/systemd/system ]; then
		systemctl --system daemon-reload >/dev/null || true
		if [ -n "$2" ]; then
			deb-systemd-invoke try-restart ayano.service >/dev/null || true
		fi
	fi
fi
