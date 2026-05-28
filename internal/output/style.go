package output

import (
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

type Config struct {
	Color   bool
	Unicode bool
	Width   int
	Writer  io.Writer
}

type styles struct {
	cfg     Config
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
		headerS: lipgloss.NewStyle(),
		faintS:  lipgloss.NewStyle(),
		panelS:  lipgloss.NewStyle().PaddingLeft(2).Width(cfg.Width - 2),
	}
	if cfg.Color {
		s.headerS = s.headerS.Bold(true).Foreground(lipgloss.ANSIColor(63))
		s.faintS = s.faintS.Foreground(lipgloss.ANSIColor(241))
		s.panelS = s.panelS.BorderForeground(lipgloss.ANSIColor(63))
	}
	s.panelS = s.panelS.Border(s.border(), false, false, false, true).PaddingLeft(1)
	return s
}

func (s styles) writeLines(lines ...string) error {
	_, err := fmt.Fprintln(s.cfg.Writer, strings.Join(lines, "\n"))
	return err
}

func (s styles) header(value string) string {
	return s.headerS.Render(value)
}

func (s styles) section(value string) string {
	return s.header(value)
}

func (s styles) faint(value string) string {
	return s.faintS.Render(value)
}

func (s styles) kv(label, value string) string {
	label = s.faintS.Render(label)
	return fmt.Sprintf("  %s %s", padRightVisible(label, 12), value)
}

func (s styles) headerBox(command, target string) string {
	title := " " + command
	if target != "" {
		sep := " · "
		if !s.cfg.Unicode {
			sep = " - "
		}
		title += sep + target
	}
	title += " "
	width := s.cfg.Width - 4
	if width < 20 {
		width = 20
	}
	style := lipgloss.NewStyle().
		Border(s.border()).
		Width(width).
		Padding(0, 1)
	if s.cfg.Color {
		style = style.BorderForeground(lipgloss.ANSIColor(63)).Foreground(lipgloss.ANSIColor(39))
	}
	return style.Render(truncate(title, width))
}

func (s styles) panel(title, body string) string {
	text := s.header(title) + "\n" + wrapText(body, s.cfg.Width-4)
	return s.panelS.Render(text)
}

func (s styles) simpleTable(headers []string, rows [][]string) string {
	return s.table(headers, rows, nil)
}

func (s styles) table(headers []string, rows [][]string, styleFn table.StyleFunc) string {
	maxWidth := s.cfg.Width - 4
	if maxWidth < 36 {
		maxWidth = 36
	}
	prepared := fitRows(headers, rows, maxWidth)
	t := table.New().
		Border(s.border()).
		BorderRow(false).
		BorderColumn(true).
		BorderHeader(true).
		Wrap(false).
		Width(maxWidth).
		Headers(headers...).
		Rows(prepared...)
	borderStyle := lipgloss.NewStyle()
	headerStyle := lipgloss.NewStyle()
	if s.cfg.Color {
		borderStyle = borderStyle.Foreground(lipgloss.ANSIColor(63))
		headerStyle = headerStyle.Bold(true).Foreground(lipgloss.ANSIColor(39))
	}
	t = t.BorderStyle(borderStyle)
	t = t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == 0 {
			return headerStyle
		}
		if styleFn != nil {
			return styleFn(row, col)
		}
		return lipgloss.NewStyle()
	})
	return indent(t.Render(), 2)
}

func (s styles) methodBadge(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "-"
	}
	style := lipgloss.NewStyle()
	if s.cfg.Color {
		style = style.Bold(true).Foreground(lipgloss.ANSIColor(0)).Background(methodColor(method)).Padding(0, 1)
		return style.Render(method)
	}
	return "[" + method + "]"
}

func (s styles) statusText(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "-"
	}
	if !s.cfg.Color {
		return status
	}
	return lipgloss.NewStyle().Foreground(statusColor(status)).Render(status)
}

func (s styles) verdictBadge(verdict string) string {
	verdict = strings.TrimSpace(verdict)
	if verdict == "" {
		verdict = "unknown"
	}
	display := verdictDisplay(verdict)
	style := lipgloss.NewStyle()
	if s.cfg.Color {
		style = style.Bold(true).Foreground(lipgloss.ANSIColor(0)).Background(verdictColor(verdict)).Padding(0, 1)
		return style.Render(display)
	}
	return "[" + display + "]"
}

func (s styles) successIcon() string {
	if s.cfg.Unicode {
		return "✓"
	}
	return "[OK]"
}

func (s styles) resultIcon(blocked, challenge bool) string {
	switch {
	case challenge:
		if s.cfg.Unicode {
			return "⚡ challenge"
		}
		return "CHALLENGE"
	case blocked:
		if s.cfg.Unicode {
			return "✗ blocked"
		}
		return "BLOCKED"
	default:
		if s.cfg.Unicode {
			return "✓ passed"
		}
		return "ok"
	}
}

func (s styles) resultLabel(category string) string {
	category = strings.TrimSpace(category)
	if category == "" {
		category = "unknown"
	}
	icon := "✗"
	if !s.cfg.Unicode {
		icon = "x"
	}
	switch category {
	case "match":
		if s.cfg.Unicode {
			icon = "✓"
		} else {
			icon = "ok"
		}
	case "drift", "auth_expired", "blocked", "error":
	default:
		icon = "-"
	}
	label := icon + " " + category
	if !s.cfg.Color {
		return label
	}
	style := lipgloss.NewStyle().Foreground(resultColor(category))
	return style.Render(label)
}

func (s styles) latencyBar(ms, maxMS float64, width int) string {
	if width <= 0 {
		width = 15
	}
	if maxMS <= 0 {
		maxMS = ms
	}
	if maxMS <= 0 {
		maxMS = 1
	}
	ratio := math.Max(0, math.Min(1, ms/maxMS))
	filled := int(math.Round(ratio * float64(width)))
	if filled == 0 && ms > 0 {
		filled = 1
	}
	if filled > width {
		filled = width
	}
	fill, empty := "█", "░"
	if !s.cfg.Unicode {
		fill, empty = "#", "-"
	}
	bar := strings.Repeat(fill, filled) + strings.Repeat(empty, width-filled)
	if s.cfg.Color {
		bar = lipgloss.NewStyle().Foreground(latencyColor(ratio)).Render(bar)
	}
	return fmt.Sprintf("%s %.0fms", bar, ms)
}

func (s styles) probeTable(results []probeRow) string {
	maxMS := 0.0
	for _, result := range results {
		if result.LatencyMS > maxMS {
			maxMS = result.LatencyMS
		}
	}
	compact := s.cfg.Width < 60
	headers := []string{"Variant", "Status", "Latency", "Result"}
	rows := make([][]string, 0, len(results))
	if compact {
		headers = []string{"Variant", "Status", "Result"}
	}
	for _, result := range results {
		status := "-"
		if result.Status > 0 {
			status = fmt.Sprint(result.Status)
		}
		label := s.resultIcon(result.Blocked, result.Challenge)
		if result.Error != "" {
			label = strings.TrimSpace(label + " " + result.Error)
		}
		if compact {
			rows = append(rows, []string{result.Variant, s.statusText(status), fmt.Sprintf("%s %.0fms", label, result.LatencyMS)})
			continue
		}
		rows = append(rows, []string{result.Variant, s.statusText(status), s.latencyBar(result.LatencyMS, maxMS, 12), label})
	}
	return s.table(headers, rows, nil)
}

func (s styles) border() lipgloss.Border {
	if s.cfg.Unicode {
		return lipgloss.RoundedBorder()
	}
	return lipgloss.ASCIIBorder()
}

type probeRow struct {
	Variant   string
	Status    int
	LatencyMS float64
	Blocked   bool
	Challenge bool
	Error     string
}

func methodColor(method string) lipgloss.ANSIColor {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return lipgloss.ANSIColor(42)
	case "POST":
		return lipgloss.ANSIColor(220)
	case "PUT", "PATCH":
		return lipgloss.ANSIColor(214)
	case "DELETE":
		return lipgloss.ANSIColor(203)
	default:
		return lipgloss.ANSIColor(244)
	}
}

func statusColor(status string) lipgloss.ANSIColor {
	switch {
	case strings.HasPrefix(status, "2"):
		return lipgloss.ANSIColor(42)
	case strings.HasPrefix(status, "3"):
		return lipgloss.ANSIColor(39)
	case strings.HasPrefix(status, "4"):
		return lipgloss.ANSIColor(214)
	case strings.HasPrefix(status, "5"):
		return lipgloss.ANSIColor(203)
	default:
		return lipgloss.ANSIColor(244)
	}
}

func verdictColor(verdict string) lipgloss.ANSIColor {
	switch verdict {
	case "no_protection":
		return lipgloss.ANSIColor(42)
	case "client_dependent":
		return lipgloss.ANSIColor(214)
	case "js_challenge":
		return lipgloss.ANSIColor(208)
	case "full_block":
		return lipgloss.ANSIColor(203)
	default:
		return lipgloss.ANSIColor(244)
	}
}

func resultColor(category string) lipgloss.ANSIColor {
	switch category {
	case "match":
		return lipgloss.ANSIColor(42)
	case "drift", "auth_expired":
		return lipgloss.ANSIColor(214)
	case "blocked", "error":
		return lipgloss.ANSIColor(203)
	default:
		return lipgloss.ANSIColor(244)
	}
}

func latencyColor(ratio float64) lipgloss.ANSIColor {
	switch {
	case ratio < 0.45:
		return lipgloss.ANSIColor(42)
	case ratio < 0.75:
		return lipgloss.ANSIColor(220)
	default:
		return lipgloss.ANSIColor(203)
	}
}

func verdictDisplay(verdict string) string {
	switch verdict {
	case "no_protection":
		return "NO PROTECTION"
	case "client_dependent":
		return "CLIENT DEPENDENT"
	case "js_challenge":
		return "JS CHALLENGE"
	case "full_block":
		return "FULL BLOCK"
	default:
		return strings.ToUpper(strings.ReplaceAll(verdict, "_", " "))
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

func indent(value string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func fitRows(headers []string, rows [][]string, maxWidth int) [][]string {
	if len(headers) == 0 {
		return rows
	}
	available := maxWidth - len(headers) - 1
	if available < len(headers)*6 {
		available = len(headers) * 6
	}
	limits := make([]int, len(headers))
	for i, header := range headers {
		limits[i] = lipgloss.Width(header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(limits) {
				continue
			}
			if width := lipgloss.Width(cell); width > limits[i] {
				limits[i] = width
			}
		}
	}
	total := 0
	for _, limit := range limits {
		total += limit
	}
	for total > available {
		largest := -1
		for i := range limits {
			if i == len(limits)-1 && len(limits) > 1 {
				continue
			}
			if limits[i] <= 8 {
				continue
			}
			if largest == -1 || limits[i] > limits[largest] {
				largest = i
			}
		}
		if largest == -1 {
			largest = 0
			for i := range limits {
				if limits[i] > limits[largest] {
					largest = i
				}
			}
		}
		if limits[largest] <= 8 {
			break
		}
		limits[largest]--
		total--
	}
	for total > available {
		largest := 0
		for i := range limits {
			if limits[i] > limits[largest] {
				largest = i
			}
		}
		if limits[largest] <= 8 {
			break
		}
		limits[largest]--
		total--
	}
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		next := make([]string, len(row))
		for i, cell := range row {
			if i < len(limits) {
				cell = truncateCell(cell, limits[i])
			}
			next[i] = cell
		}
		out = append(out, next)
	}
	return out
}

func truncateCell(value string, limit int) string {
	if lipgloss.Width(value) <= limit {
		return value
	}
	if strings.Contains(value, "\x1b[") {
		value = stripANSI(value)
	}
	return truncate(value, limit)
}

func padRightVisible(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func stripANSI(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); {
		if value[i] == '\x1b' && i+1 < len(value) && value[i+1] == '[' {
			i += 2
			for i < len(value) {
				ch := value[i]
				i++
				if ch >= '@' && ch <= '~' {
					break
				}
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteByte(value[i])
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}
