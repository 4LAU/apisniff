package replay

import (
	"bufio"
	"os"
	"strings"
)

type Cookie struct {
	Domain string
	Name   string
	Value  string
}

func ParseCookieFile(path string) ([]Cookie, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var cookies []Cookie
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}
		cookies = append(cookies, Cookie{Domain: parts[0], Name: parts[5], Value: parts[6]})
	}
	return cookies, scanner.Err()
}

func CookiesForHost(cookies []Cookie, host string) string {
	var pairs []string
	for _, cookie := range cookies {
		if cookie.Domain == "" {
			continue
		}
		if strings.HasPrefix(cookie.Domain, ".") {
			suffix := strings.TrimPrefix(cookie.Domain, ".")
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				pairs = append(pairs, cookie.Name+"="+cookie.Value)
			}
			continue
		}
		if host == cookie.Domain {
			pairs = append(pairs, cookie.Name+"="+cookie.Value)
		}
	}
	return strings.Join(pairs, "; ")
}
