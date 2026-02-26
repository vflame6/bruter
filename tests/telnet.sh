#!/bin/bash
# Telnet test — no standard Docker image with auth
# Option: use a custom image or test against a known telnet device
# For now, this is a placeholder — needs a telnet server with login/password auth
echo "NOTE: No standard Docker image for authenticated telnet."
echo "To test: set up a VM or device with telnet enabled, then run:"
echo "  go run . telnet -u tests/usernames.txt -p tests/passwords.txt -t <target> -D"
