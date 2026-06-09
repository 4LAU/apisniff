package capture

import (
	"bufio"
	"os"
	"path/filepath"

	"github.com/4LAU/apisniff/internal/model"
)

type JSONLWriter struct {
	finalPath string
	tempPath  string
	file      *os.File
	buffered  *bufio.Writer
	count     int
	closed    bool
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".flows-*.jsonl")
	if err != nil {
		return nil, err
	}
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return nil, err
	}
	return &JSONLWriter{
		finalPath: path,
		tempPath:  temp.Name(),
		file:      temp,
		buffered:  bufio.NewWriter(temp),
	}, nil
}

func (w *JSONLWriter) Write(flow model.CapturedFlow) error {
	if w.closed {
		return os.ErrClosed
	}
	line, err := flow.ToJSONL()
	if err != nil {
		return err
	}
	if _, err := w.buffered.WriteString(line + "\n"); err != nil {
		return err
	}
	w.count++
	return nil
}

func (w *JSONLWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.buffered.Flush(); err != nil {
		w.file.Close()
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	return os.Rename(w.tempPath, w.finalPath)
}

func (w *JSONLWriter) Count() int {
	return w.count
}
