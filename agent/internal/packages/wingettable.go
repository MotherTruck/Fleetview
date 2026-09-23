package packages

import "strings"

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// parseWingetTable parses winget's column-aligned console table output
// (`winget list` / `winget upgrade`). Columns aren't delimited, so field
// boundaries are inferred from where each header word starts, and every data
// row is sliced at those same byte offsets — this survives values containing
// embedded spaces (package names in particular), unlike splitting on
// whitespace. winget's headers are localized to the system's display
// language, so this only parses English output as written.
func parseWingetTable(output string, columns []string) []map[string]string {
	lines := strings.Split(output, "\n")
	headerIndex := -1
	starts := make([]int, len(columns))
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		found := true
		for _, column := range columns {
			if !strings.Contains(line, column) {
				found = false
				break
			}
		}
		if !found {
			continue
		}
		for c, column := range columns {
			starts[c] = strings.Index(line, column)
		}
		headerIndex = i
		break
	}
	if headerIndex == -1 {
		return nil
	}
	dataStart := headerIndex + 1
	if dataStart < len(lines) {
		separator := strings.TrimRight(lines[dataStart], "\r")
		if separator != "" && strings.Trim(separator, "-") == "" {
			dataStart++
		}
	}
	rows := []map[string]string{}
	for _, line := range lines[dataStart:] {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := make(map[string]string, len(columns))
		for i, column := range columns {
			start := starts[i]
			end := len(line)
			if i+1 < len(starts) && starts[i+1] < len(line) {
				end = starts[i+1]
			}
			if start >= len(line) {
				row[column] = ""
				continue
			}
			if end > len(line) {
				end = len(line)
			}
			if end < start {
				end = start
			}
			row[column] = strings.TrimSpace(line[start:end])
		}
		rows = append(rows, row)
	}
	return rows
}
