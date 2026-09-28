#!/bin/bash
# Lab-only entrypoint: starts Postfix and Dovecot, then blocks so the
# container stays up. Not a production init system.
set -e

mkdir -p /var/spool/postfix/private
chown postfix:postfix /var/spool/postfix/private

postfix start-fg &
POSTFIX_PID=$!

dovecot -F &
DOVECOT_PID=$!

trap "kill $POSTFIX_PID $DOVECOT_PID 2>/dev/null" TERM INT

wait -n
