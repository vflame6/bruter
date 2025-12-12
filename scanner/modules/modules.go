package modules

import (
	"github.com/vflame6/bruter/utils"
	"net"
	"time"
)

// CommandChecker is a type function for service checker function
// the return values are:
// DEFAULT (bool) for test if the target has default credentials
// ENCRYPTION (bool) for test if the target is using encryption
// ERROR (error) for connection errors
// if checker could not be implemented for target service, the checker must return false, false, nil
type CommandChecker func(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error)

// CommandHandler is a type function for one bruteforce thread
// the return values are:
// IsConnected (bool) to test if connection to the target is successful
// IsAuthenticated (bool) to test if authentication is successful
type CommandHandler func(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool)
