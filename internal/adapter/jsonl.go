package adapter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/4LAU/apisniff/internal/model"
)

func LoadJSONL(path string) ([]model.CapturedFlow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 100*1024*1024)
	var flows []model.CapturedFlow
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var flow model.CapturedFlow
		if err := json.Unmarshal(line, &flow); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		flows = append(flows, flow)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return flows, nil
}
