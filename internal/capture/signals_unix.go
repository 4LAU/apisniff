//go:build !windows

package capture

import (
	"os"
	"syscall"
)

var gracefulSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
