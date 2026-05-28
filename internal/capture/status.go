package capture

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type statusLine struct {
	writer  io.Writer
	message string
	count   *atomic.Int64
	done    chan struct{}
	width   int
}

func newStatusLine(w io.Writer, message string, count *atomic.Int64) *statusLine {
	if w == nil {
		w = io.Discard
	}
	return &statusLine{
		writer:  w,
		message: message,
		count:   count,
		done:    make(chan struct{}),
		width:   80,
	}
}

func (s *statusLine) start() {
	go func() {
		dots := 0
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				s.clear()
				return
			case <-ticker.C:
				dots = (dots % 3) + 1
				s.render(dots)
			}
		}
	}()
}

func (s *statusLine) stop() {
	close(s.done)
	time.Sleep(20 * time.Millisecond)
}

func (s *statusLine) render(dots int) {
	n := s.count.Load()
	dotStr := strings.Repeat(".", dots) + strings.Repeat(" ", 3-dots)
	line := fmt.Sprintf("\r%s%s %d flows", s.message, dotStr, n)
	pad := s.width - len(line)
	if pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	fmt.Fprint(s.writer, line)
}

func (s *statusLine) clear() {
	// \r moves to start, then overwrite the full line (including any ^C the terminal echoed)
	fmt.Fprintf(s.writer, "\r%s\r", strings.Repeat(" ", s.width))
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
