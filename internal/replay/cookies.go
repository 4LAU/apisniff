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
		line := strings.TrimRight(scanner.Text(), "\r\n")
		line = strings.TrimPrefix(line, "#HttpOnly_")
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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var pairs []string
	for _, cookie := range cookies {
		domain := strings.ToLower(strings.TrimSuffix(cookie.Domain, "."))
		if domain == "" {
			continue
		}
		if strings.HasPrefix(domain, ".") {
			suffix := strings.TrimPrefix(domain, ".")
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				pairs = append(pairs, cookie.Name+"="+cookie.Value)
			}
			continue
		}
		if host == domain {
			pairs = append(pairs, cookie.Name+"="+cookie.Value)
		}
	}
	return strings.Join(pairs, "; ")
}
