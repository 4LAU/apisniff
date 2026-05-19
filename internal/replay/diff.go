package replay

import (
	"encoding/json"
	"fmt"
	"math"
)

const maxShapeDepth = 3

func CompareShape(originalBody, replayedBody []byte) (bool, map[string]any) {
	var original any
	var replayed any
	origParsed := len(originalBody) > 0 && json.Unmarshal(originalBody, &original) == nil
	replParsed := len(replayedBody) > 0 && json.Unmarshal(replayedBody, &replayed) == nil
	if origParsed != replParsed {
		return false, map[string]any{"json_parse_mismatch": map[string]any{"was": origParsed, "now": replParsed}}
	}
	if !origParsed && !replParsed {
		return true, nil
	}
	diff := diffShapes(shape(original, maxShapeDepth), shape(replayed, maxShapeDepth), "")
	return len(diff) == 0, diff
}

func AssignCategory(flowStatus int, replayedStatus int, hasAuth bool, bodyMatch bool, originalSize int, replayedSize int, err error) (string, bool) {
	if err != nil || replayedStatus == 0 {
		return "error", false
	}
	statusMatch := flowStatus == replayedStatus
	orig2xx := flowStatus >= 200 && flowStatus < 300
	if (replayedStatus == 401 || replayedStatus == 403) && orig2xx {
		if hasAuth {
			return "auth_expired", statusMatch
		}
		return "blocked", statusMatch
	}
	if (replayedStatus == 403 || replayedStatus == 429 || replayedStatus == 503) && orig2xx && !hasAuth {
		return "blocked", statusMatch
	}
	if !statusMatch || !bodyMatch {
		return "drift", statusMatch
	}
	if originalSize > 0 {
		delta := math.Abs(float64(replayedSize-originalSize)) / float64(originalSize)
		if delta > 0.5 {
			return "drift", statusMatch
		}
	}
	return "match", statusMatch
}

func shape(value any, depth int) any {
	if depth <= 0 {
		return fmt.Sprintf("%T", value)
	}
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, child := range typed {
			out[key] = shape(child, depth-1)
		}
		return out
	case []any:
		if len(typed) == 0 {
			return []any{}
		}
		first := shape(typed[0], depth-1)
		firstType := fmt.Sprintf("%T", typed[0])
		for _, item := range typed[1:] {
			if fmt.Sprintf("%T", item) != firstType {
				return []any{"mixed"}
			}
		}
		return []any{first}
	default:
		switch value.(type) {
		case string:
			return "str"
		case float64:
			return "float64"
		case bool:
			return "bool"
		case nil:
			return "<nil>"
		default:
			return fmt.Sprintf("%T", value)
		}
	}
}

func diffShapes(original, replayed any, path string) map[string]any {
	diffs := map[string]any{}
	origMap, origIsMap := original.(map[string]any)
	replMap, replIsMap := replayed.(map[string]any)
	if origIsMap && replIsMap {
		seen := map[string]struct{}{}
		for key := range origMap {
			seen[key] = struct{}{}
		}
		for key := range replMap {
			seen[key] = struct{}{}
		}
		for key := range seen {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if _, ok := origMap[key]; !ok {
				diffs[childPath] = map[string]any{"was": nil, "now": replMap[key]}
			} else if _, ok := replMap[key]; !ok {
				diffs[childPath] = map[string]any{"was": origMap[key], "now": nil}
			} else {
				for diffPath, diff := range diffShapes(origMap[key], replMap[key], childPath) {
					diffs[diffPath] = diff
				}
			}
		}
		return diffs
	}
	if fmt.Sprintf("%#v", original) != fmt.Sprintf("%#v", replayed) {
		if path == "" {
			path = "root"
		}
		diffs[path] = map[string]any{"was": original, "now": replayed}
	}
	return diffs
}
