#!/bin/bash
# SSH public key auth test — reuse local SSH or a Docker container
# Generate a test key pair
ssh-keygen -t ed25519 -f /tmp/bruter-test-key -N "" -q 2>/dev/null

echo "NOTE: To test sshkey module, add /tmp/bruter-test-key.pub to a target's authorized_keys."
echo "Then run:"
echo "  go run . sshkey -u root -p /tmp/bruter-test-key -t <target> -D"
echo ""
echo "For Docker:"
echo "  docker run -d --name ssh-key-bruter -p 127.0.0.1:2222:22 lscr.io/linuxserver/openssh-server"
echo "  docker cp /tmp/bruter-test-key.pub ssh-key-bruter:/config/.ssh/authorized_keys"
echo "  go run . sshkey -u linuxserver.io -p /tmp/bruter-test-key -t 127.0.0.1:2222 -D"
