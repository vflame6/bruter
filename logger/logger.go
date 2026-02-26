// Package logger provides a configurable logging utility for CLI applications.
// It supports multiple log levels (FATAL, INFO, DEBUG, SUCCESS) with two modes:
// QUIET mode (minimal output) and DEBUG mode (verbose output with timestamps).
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ProgressClearer is called before each log line to clear any active
// progress/status line from the terminal. Set via SetProgressClearer.
type ProgressClearer func()

// Logger represents a configurable logger instance.
type Logger struct {
	quiet         bool
	debug         bool
	verbose       bool
	output        io.Writer
	mu            sync.Mutex
	clearProgress ProgressClearer
}

// Default logger instance for global access.
var defaultLogger *Logger

func init() {
	// Initialize with default settings (neither quiet nor debug).
	defaultLogger = &Logger{
		quiet:  false,
		debug:  false,
		output: os.Stdout,
	}
}

// New creates a new Logger instance with the specified configuration.
// Returns an error if both quiet and debug are true.
func New(quiet, debug bool) (*Logger, error) {
	if quiet && debug {
		return nil, fmt.Errorf("logger: cannot enable both QUIET and DEBUG modes simultaneously")
	}

	return &Logger{
		quiet:  quiet,
		debug:  debug,
		output: os.Stdout,
	}, nil
}

// Init initializes the default global logger with the specified configuration.
// Returns an error if both quiet and debug are true.
func Init(quiet, debug bool) error {
	logger, err := New(quiet, debug)
	if err != nil {
		return err
	}
	defaultLogger = logger
	return nil
}

// SetOutput sets the output destination for the logger.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// SetOutput sets the output destination for the default logger.
func SetOutput(w io.Writer) {
	defaultLogger.SetOutput(w)
}

// SetProgressClearer registers a function that clears the progress bar
// before each log line is printed. This prevents log output from
// colliding with the progress status line on the terminal.
func (l *Logger) SetProgressClearer(fn ProgressClearer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearProgress = fn
}

// SetProgressClearer registers a progress clearer on the default logger.
func SetProgressClearer(fn ProgressClearer) {
	defaultLogger.SetProgressClearer(fn)
}

// clearLine clears any active progress bar before printing a log line.
// Must be called while l.mu is held.
func (l *Logger) clearLine() {
	if l.clearProgress != nil {
		l.clearProgress()
	}
}

// timestamp returns the current timestamp in a standard format.
func timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Fatal logs a fatal message and exits the program.
// In QUIET mode: prints message without prefix/timestamp.
// In DEBUG mode: prints with timestamp and [FATAL] prefix.
// In normal mode: prints with timestamp and [FATAL] prefix.
func (l *Logger) Fatal(v ...interface{}) {
	l.mu.Lock()

	l.clearLine()
	msg := fmt.Sprint(v...)

	if l.quiet {
		fmt.Fprintln(l.output, msg)
	} else {
		fmt.Fprintf(l.output, "%s [FATAL] %s\n", timestamp(), msg)
	}

	l.mu.Unlock()
	os.Exit(1)
}

// Fatalf logs a formatted fatal message and exits the program.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mu.Lock()

	l.clearLine()
	msg := fmt.Sprintf(format, v...)

	if l.quiet {
		fmt.Fprintln(l.output, msg)
	} else {
		fmt.Fprintf(l.output, "%s [FATAL] %s\n", timestamp(), msg)
	}

	l.mu.Unlock()
	os.Exit(1)
}

// Fatal logs a fatal message using the default logger and exits.
func Fatal(v ...interface{}) {
	defaultLogger.Fatal(v...)
}

// Fatalf logs a formatted fatal message using the default logger and exits.
func Fatalf(format string, v ...interface{}) {
	defaultLogger.Fatalf(format, v...)
}

// Info logs an informational message.
// In QUIET mode: message is suppressed.
// In DEBUG mode: prints with timestamp and [*] prefix.
// In normal mode: prints with timestamp and [*] prefix.
func (l *Logger) Info(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.quiet {
		return
	}

	l.clearLine()
	msg := fmt.Sprint(v...)
	fmt.Fprintf(l.output, "%s [*] %s\n", timestamp(), msg)
}

// Infof logs a formatted informational message.
func (l *Logger) Infof(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.quiet {
		return
	}

	l.clearLine()
	msg := fmt.Sprintf(format, v...)
	fmt.Fprintf(l.output, "%s [*] %s\n", timestamp(), msg)
}

// Info logs an informational message using the default logger.
func Info(v ...interface{}) {
	defaultLogger.Info(v...)
}

// Infof logs a formatted informational message using the default logger.
func Infof(format string, v ...interface{}) {
	defaultLogger.Infof(format, v...)
}

// Debug logs a debug message.
// Only printed when DEBUG mode is enabled.
// Prints with timestamp and [DEBUG] prefix.
func (l *Logger) Debug(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.debug {
		return
	}

	l.clearLine()
	msg := fmt.Sprint(v...)
	fmt.Fprintf(l.output, "%s [DEBUG] %s\n", timestamp(), msg)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.debug {
		return
	}

	l.clearLine()
	msg := fmt.Sprintf(format, v...)
	fmt.Fprintf(l.output, "%s [DEBUG] %s\n", timestamp(), msg)
}

// Debug logs a debug message using the default logger.
func Debug(v ...interface{}) {
	defaultLogger.Debug(v...)
}

// Debugf logs a formatted debug message using the default logger.
func Debugf(format string, v ...interface{}) {
	defaultLogger.Debugf(format, v...)
}

// Success logs a success message.
// In QUIET mode: prints message without prefix/timestamp.
// In DEBUG mode: prints with timestamp and [+] prefix.
// In normal mode: prints with timestamp and [+] prefix.
func (l *Logger) Success(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.clearLine()
	msg := fmt.Sprint(v...)

	if l.quiet {
		fmt.Fprintln(l.output, msg)
	} else {
		fmt.Fprintf(l.output, "%s [+] %s\n", timestamp(), msg)
	}
}

// Successf logs a formatted success message.
func (l *Logger) Successf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.clearLine()
	msg := fmt.Sprintf(format, v...)

	if l.quiet {
		fmt.Fprintln(l.output, msg)
	} else {
		fmt.Fprintf(l.output, "%s [+] %s\n", timestamp(), msg)
	}
}

// Success logs a success message using the default logger.
func Success(v ...interface{}) {
	defaultLogger.Success(v...)
}

// Successf logs a formatted success message using the default logger.
func Successf(format string, v ...interface{}) {
	defaultLogger.Successf(format, v...)
}

// IsQuiet returns whether the logger is in quiet mode.
func (l *Logger) IsQuiet() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.quiet
}

// IsQuiet returns whether the default logger is in quiet mode.
func IsQuiet() bool {
	return defaultLogger.IsQuiet()
}

// SetVerbose enables or disables verbose mode on the logger instance.
func (l *Logger) SetVerbose(v bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = v
}

// SetVerbose enables or disables verbose mode on the default logger.
func SetVerbose(v bool) {
	defaultLogger.SetVerbose(v)
}

// Verbosef logs a formatted verbose message with a timestamp prefix.
// Only prints when verbose mode is enabled. Independent of quiet/debug modes.
func (l *Logger) Verbosef(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.verbose {
		return
	}
	l.clearLine()
	msg := fmt.Sprintf(format, v...)
	fmt.Fprintf(l.output, "%s [VERBOSE] %s\n", timestamp(), msg)
}

// Verbosef logs a formatted verbose message using the default logger.
func Verbosef(format string, v ...interface{}) {
	defaultLogger.Verbosef(format, v...)
}
