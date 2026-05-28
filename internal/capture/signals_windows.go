//go:build windows

package capture

import "os"

var gracefulSignals = []os.Signal{os.Interrupt}
