package adapter

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/4LAU/apisniff-go/internal/model"
)

const maxImportBytes = 200 * 1024 * 1024

var harLogRe = regexp.MustCompile(`^\{\s*"log"\s*:`)

func Detect(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown", err
	}
	if info.Size() > maxImportBytes {
		return "unknown", ErrTooLarge{Size: info.Size()}
	}
	file, err := os.Open(path)
	if err != nil {
		return "unknown", err
	}
	defer file.Close()
	buf := make([]byte, 1024)
	n, _ := file.Read(buf)
	head := strings.TrimSpace(string(buf[:n]))
	if harLogRe.MatchString(head) {
		return "har", nil
	}
	if strings.Contains(head, "<items") {
		return "burp", nil
	}
	if strings.HasPrefix(head, "{") {
		firstLine := strings.SplitN(head, "\n", 2)[0]
		var obj map[string]any
		if json.Unmarshal([]byte(firstLine), &obj) == nil {
			if _, ok := obj["method"]; ok {
				return "jsonl", nil
			}
		}
	}
	return "unknown", nil
}

type ErrTooLarge struct {
	Size int64
}

func (e ErrTooLarge) Error() string {
	return "input file is too large"
}

func LoadFlows(path string) ([]model.CapturedFlow, string, error) {
	format, err := Detect(path)
	if err != nil {
		return nil, format, err
	}
	switch format {
	case "jsonl":
		flows, err := LoadJSONL(path)
		return flows, format, err
	case "har":
		flows, err := LoadHAR(path)
		return flows, format, err
	case "burp":
		flows, err := LoadBurp(path)
		return flows, format, err
	default:
		return nil, format, nil
	}
}
