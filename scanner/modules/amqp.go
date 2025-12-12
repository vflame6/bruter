package modules

import (
	"crypto/tls"
	"errors"
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
	"net"
	"time"
)

// AMQPChecker is an implementation of CommandChecker for AMQP service
func AMQPChecker(target net.IP, port int, timeout time.Duration, dialer *utils.ProxyAwareDialer, defaultUsername, defaultPassword string) (bool, bool, error) {
	success := false
	secure := false

	// try with encryption first
	probe, err := ProbeAMQP(target, port, true, dialer, defaultUsername, defaultPassword)
	if err == nil {
		secure = true
		if probe {
			success = true
		}
	} else {
		logger.Debugf("failed to connect to AMQP with encryption on %s:%d, trying plaintext", target, port)
		// connect via plaintext FTP
		probe, err = ProbeAMQP(target, port, false, dialer, defaultUsername, defaultPassword)
		if err == nil {
			if probe {
				success = true
			}
		} else {
			// if nothing succeeded, return error
			return false, false, err
		}
	}

	return success, secure, nil
}

// AMQPHandler is an implementation of CommandHandler for AMQP service
func AMQPHandler(target net.IP, port int, encryption bool, timeout time.Duration, dialer *utils.ProxyAwareDialer, username, password string) (bool, bool) {
	probe, err := ProbeAMQP(target, port, encryption, dialer, username, password)
	if err != nil {
		// not connected
		return false, false
	}

	// connected and authenticated or not
	return true, probe
}

func ProbeAMQP(ip net.IP, port int, encryption bool, dialer *utils.ProxyAwareDialer, username, password string) (bool, error) {
	var conn *amqp.Connection
	var endpoint string
	var err error

	if encryption {
		endpoint = fmt.Sprintf("amqps://%s:%s@%s:%d/", username, password, ip.String(), port)
		conn, err = amqp.DialConfig(endpoint, amqp.Config{
			Dial: func(network, addr string) (net.Conn, error) {
				tlsConfig := utils.GetTLSConfig()
				c, err := dialer.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return tls.Client(c, tlsConfig), nil
			},
		})
	} else {
		endpoint = fmt.Sprintf("amqp://%s:%s@%s:%d/", username, password, ip.String(), port)
		conn, err = amqp.DialConfig(endpoint, amqp.Config{
			Dial: dialer.Dial,
		})
	}

	if err != nil {
		if errors.Is(err, amqp.ErrCredentials) {
			// failed authentication
			return false, nil
		}
		// failed connection
		return false, err
	}

	defer conn.Close()
	// successful authentication or unusual error
	return true, nil
}
