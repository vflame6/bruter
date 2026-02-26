#!/bin/bash
# SMPP test — limited Docker options
# smppex/smppex could work as a mock SMPP server
echo "NOTE: SMPP testing requires a mock SMSC. Consider:"
echo "  - A custom Go SMPP server mock"
echo "  - smppex (Elixir-based)"
echo "Run manually: go run . smpp -u tests/usernames.txt -p tests/passwords.txt -t <target>:2775 -D"
