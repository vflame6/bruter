package modules

import (
	"bufio"
	"strings"
)

const iacByte = 0xFF // Telnet Interpret As Command

// stripIAC removes Telnet IAC (0xFF) negotiation sequences from raw bytes.
// IAC sequences are 3 bytes: IAC + command + option.
// Any lone 0xFF (without 2 following bytes) is also stripped.
func stripIAC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == iacByte {
			i += 3 // skip IAC + command + option
			continue
		}
		out = append(out, data[i])
		i++
	}
	return out
}

// readUntilPrompt reads from reader one byte at a time, strips IAC sequences,
// and returns the accumulated text once any of the given prompt strings is found
// (case-insensitive). Returns the full accumulated text and any read error.
func readUntilPrompt(reader *bufio.Reader, prompts []string) (string, error) {
	var buf []byte
	rawBuf := make([]byte, 1)

	for {
		n, err := reader.Read(rawBuf)
		if n > 0 {
			cleaned := stripIAC(rawBuf[:n])
			buf = append(buf, cleaned...)

			lower := strings.ToLower(string(buf))
			for _, p := range prompts {
				if strings.Contains(lower, strings.ToLower(p)) {
					return string(buf), nil
				}
			}
		}
		if err != nil {
			return string(buf), err
		}
	}
}
