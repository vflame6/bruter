package modules

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RTSPHandler is an implementation of ModuleHandler for RTSP Basic authentication.
// Sends a DESCRIBE request with Authorization: Basic header and checks the response code.
func RTSPHandler(_ context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	rtspURL := fmt.Sprintf("rtsp://%s/", addr)
	creds := base64.StdEncoding.EncodeToString(
		[]byte(credential.Username + ":" + credential.Password),
	)
	request := fmt.Sprintf(
		"DESCRIBE %s RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic %s\r\nAccept: application/sdp\r\n\r\n",
		rtspURL, creds,
	)

	if _, err = fmt.Fprint(conn, request); err != nil {
		return false, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	fields := strings.Fields(statusLine) // ["RTSP/1.0", "200", "OK"]
	if len(fields) < 2 {
		return false, fmt.Errorf("invalid RTSP response: %q", statusLine)
	}

	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return false, fmt.Errorf("non-numeric status %q: %w", fields[1], err)
	}

	switch code {
	case 200:
		return true, nil
	case 401, 403:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected RTSP status %d", code)
	}
}
