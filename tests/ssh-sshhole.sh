#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container_name="bruter-sshhole-test-$$"
container_image="bruter-sshhole-test:$$"
work_dir="$(mktemp -d)"
scan_file="$work_dir/scan.gnmap"

cleanup() {
	docker rm -f "$container_name" >/dev/null 2>&1 || true
	docker image rm -f "$container_image" >/dev/null 2>&1 || true
	rm -rf "$work_dir"
}
trap cleanup EXIT

docker build -q -t "$container_image" -f - "$work_dir" <<'DOCKERFILE'
FROM alpine@sha256:19b4bcc4f60e99dd5ebdca0cbce22c503bbcff197549d7e19dab4f22254dc864
RUN apk add --no-cache openssh-server=8.8_p1-r1 \
	&& ssh-keygen -A \
	&& adduser -D alice \
	&& echo 'alice:correcthorse' | chpasswd \
	&& adduser -D locked \
	&& sed -i 's/^locked:[^:]*/locked:*/' /etc/shadow \
	&& printf '%s\n' \
		'Port 22' \
		'ListenAddress 0.0.0.0' \
		'HostKey /etc/ssh/ssh_host_ed25519_key' \
		'PermitRootLogin yes' \
		'PasswordAuthentication yes' \
		'PermitEmptyPasswords no' \
		'AllowUsers root alice locked' \
		> /etc/ssh/sshd_config
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
DOCKERFILE

docker run -d --name "$container_name" -p 127.0.0.1::22 "$container_image" >/dev/null

port="$(docker port "$container_name" 22/tcp | awk -F: 'NR == 1 { print $NF }')"
if [[ -z "$port" ]]; then
	echo "could not determine the container SSH port" >&2
	exit 1
fi

ready=false
for _ in {1..30}; do
	if docker logs "$container_name" 2>&1 | grep -q 'Server listening'; then
		ready=true
		break
	fi
	sleep 1
done
if [[ "$ready" != true ]]; then
	echo "vulnerable SSH container did not become ready" >&2
	docker logs "$container_name" >&2 || true
	exit 1
fi

printf '# Nmap test scan\nHost: 127.0.0.1 () Ports: %s/open/tcp//ssh///\n' "$port" > "$scan_file"

cd "$root_dir"
go run . ssh --vulns -t "127.0.0.1:$port" -f -c 1
