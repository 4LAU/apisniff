package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type Config struct {
	Color  bool
	Width  int
	Writer io.Writer
}

type styles struct {
	cfg     Config
	titleS  lipgloss.Style
	headerS lipgloss.Style
	faintS  lipgloss.Style
	panelS  lipgloss.Style
}

func newStyles(cfg Config) styles {
	if cfg.Writer == nil {
		cfg.Writer = io.Discard
	}
	if cfg.Width <= 0 {
		cfg.Width = 80
	}
	if cfg.Width < 40 {
		cfg.Width = 40
	}
	if cfg.Width > 120 {
		cfg.Width = 120
	}
	s := styles{
		cfg:     cfg,
		titleS:  lipgloss.NewStyle(),
		headerS: lipgloss.NewStyle(),
		faintS:  lipgloss.NewStyle(),
		panelS:  lipgloss.NewStyle().PaddingLeft(2).Width(cfg.Width - 2),
	}
	if cfg.Color {
		s.titleS = s.titleS.Bold(true).Foreground(lipgloss.Color("39"))
		s.headerS = s.headerS.Bold(true).Foreground(lipgloss.Color("63"))
		s.faintS = s.faintS.Foreground(lipgloss.Color("241"))
		s.panelS = s.panelS.Border(lipgloss.ASCIIBorder(), false, false, false, true).BorderForeground(lipgloss.Color("63")).PaddingLeft(1)
	}
	return s
}

func (s styles) writeLines(lines ...string) error {
	_, err := fmt.Fprintln(s.cfg.Writer, strings.Join(lines, "\n"))
	return err
}

func (s styles) title(value string) string {
	return s.titleS.Render(value)
}

func (s styles) header(value string) string {
	return s.headerS.Render(value)
}

func (s styles) empty(value string) string {
	return "  " + s.faintS.Render(value)
}

func (s styles) summary(label, value string) string {
	label = s.faintS.Render(label + ":")
	return fmt.Sprintf("%-16s %s", label, value)
}

func (s styles) row(first, second, third string) string {
	limit := s.cfg.Width - 28
	if limit < 12 {
		limit = 12
	}
	return fmt.Sprintf("  %-14s %-*s %s", first, limit, truncate(second, limit), third)
}

func (s styles) panel(title, body string) string {
	text := s.header(title) + "\n" + wrapText(body, s.cfg.Width-4)
	return s.panelS.Render(text)
}

func (s styles) methodBadge(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "-"
	}
	style := lipgloss.NewStyle()
	if s.cfg.Color {
		style = style.Bold(true).Foreground(lipgloss.Color("0")).Background(methodColor(method)).Padding(0, 1)
		return style.Render(method)
	}
	return "[" + method + "]"
}

func (s styles) statusBadge(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		status = "-"
	}
	style := lipgloss.NewStyle()
	if s.cfg.Color {
		style = style.Bold(true).Foreground(lipgloss.Color("0")).Background(statusColor(status)).Padding(0, 1)
		return style.Render(status)
	}
	return "[" + status + "]"
}

func (s styles) verdictBadge(verdict string) string {
	verdict = strings.TrimSpace(verdict)
	if verdict == "" {
		verdict = "unknown"
	}
	style := lipgloss.NewStyle()
	if s.cfg.Color {
		style = style.Bold(true).Foreground(lipgloss.Color("0")).Background(verdictColor(verdict)).Padding(0, 1)
		return style.Render(verdict)
	}
	return "[" + verdict + "]"
}

func methodColor(method string) lipgloss.TerminalColor {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return lipgloss.Color("42")
	case "POST":
		return lipgloss.Color("220")
	case "PUT", "PATCH":
		return lipgloss.Color("214")
	case "DELETE":
		return lipgloss.Color("203")
	default:
		return lipgloss.Color("244")
	}
}

func statusColor(status string) lipgloss.TerminalColor {
	switch {
	case strings.HasPrefix(status, "2"):
		return lipgloss.Color("42")
	case strings.HasPrefix(status, "3"):
		return lipgloss.Color("39")
	case strings.HasPrefix(status, "4"):
		return lipgloss.Color("214")
	case strings.HasPrefix(status, "5"):
		return lipgloss.Color("203")
	default:
		return lipgloss.Color("244")
	}
}

func verdictColor(verdict string) lipgloss.TerminalColor {
	switch verdict {
	case "no_protection":
		return lipgloss.Color("42")
	case "client_dependent":
		return lipgloss.Color("214")
	case "js_challenge":
		return lipgloss.Color("208")
	case "full_block":
		return lipgloss.Color("203")
	default:
		return lipgloss.Color("244")
	}
}

func truncate(value string, limit int) string {
	if lipgloss.Width(value) <= limit {
		return value
	}
	runes := []rune(value)
	if limit <= 3 {
		for len(runes) > 0 && lipgloss.Width(string(runes)) > limit {
			runes = runes[:len(runes)-1]
		}
		return string(runes)
	}
	for len(runes) > 0 && lipgloss.Width(string(runes))+3 > limit {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "..."
}

func wrapText(value string, width int) string {
	if width < 20 {
		width = 20
	}
	var lines []string
	for _, paragraph := range strings.Split(value, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := words[0]
		for _, word := range words[1:] {
			if lipgloss.Width(line)+1+lipgloss.Width(word) > width {
				lines = append(lines, line)
				line = word
				continue
			}
			line += " " + word
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
