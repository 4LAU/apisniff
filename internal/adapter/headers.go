package adapter

import "strings"

func joinHeaderValues(grouped map[string][]string) map[string]string {
	out := map[string]string{}
	for key, values := range grouped {
		if key == "set-cookie" {
			out[key] = strings.Join(values, "\n")
		} else {
			out[key] = strings.Join(values, ", ")
		}
	}
	return out
}
