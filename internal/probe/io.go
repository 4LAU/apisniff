package probe

import (
	"io"
)

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(reader, limit))
}
