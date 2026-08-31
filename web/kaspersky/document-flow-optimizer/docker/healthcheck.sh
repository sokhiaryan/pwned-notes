#!/bin/bash
set -euo pipefail

HOST="127.0.0.1"
PORT="8000"
REQUEST_PATH="/healthz"

exec 3<>"/dev/tcp/${HOST}/${PORT}"
printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${REQUEST_PATH}" "${HOST}" >&3

status_line=$(head -n 1 <&3)
exec 3>&- 3<&-

echo "${status_line}" | grep -Eq ' 200 '
