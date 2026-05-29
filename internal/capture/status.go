package capture

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/term"
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
	width := 80
	if file, ok := w.(*os.File); ok {
		if cols, _, err := term.GetSize(file.Fd()); err == nil && cols > 0 {
			width = cols
		}
	}
	return &statusLine{
		writer:  w,
		message: message,
		count:   count,
		done:    make(chan struct{}),
		width:   width,
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
	line := fmt.Sprintf("%s%s %d flows", s.message, dotStr, n)
	if len(line) >= s.width {
		line = line[:s.width-1]
	}
	fmt.Fprintf(s.writer, "\033[2K\r%s", line)
}

func (s *statusLine) clear() {
	fmt.Fprint(s.writer, "\033[2K\r")
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
