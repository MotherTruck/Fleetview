package packages

import "testing"

// This fixture is a best-effort reconstruction of winget's documented
// console table layout (left-aligned columns, header, dash separator, rows),
// not output captured from a real install — there is no Windows environment
// available to verify against. It exercises the offset-based column parsing
// itself, which is the part most likely to be subtly wrong.
const wingetListSample = "" +
	"Name                              Id                          Version        Source\n" +
	"--------------------------------------------------------------------------------------\n" +
	"7-Zip 23.01 (x64)                 7zip.7zip                   23.01          winget\n" +
	"Microsoft Edge WebView2 Runtime   Microsoft.EdgeWebView2Rt     121.0.2277.83  winget\n" +
	"Notepad++ (64-bit x64)            Notepad++.Notepad++          8.6.2          winget\n"

const wingetUpgradeSample = "" +
	"Name              Id                    Version    Available  Source\n" +
	"----------------------------------------------------------------------\n" +
	"7-Zip 23.01       7zip.7zip             23.01      24.05      winget\n" +
	"Google Chrome     Google.Chrome         120.0.1    121.0.5    winget\n"

func TestParseWingetTableInstalledList(t *testing.T) {
	rows := parseWingetTable(wingetListSample, []string{"Name", "Id", "Version", "Source"})
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d: %#v", len(rows), rows)
	}
	if rows[0]["Name"] != "7-Zip 23.01 (x64)" || rows[0]["Id"] != "7zip.7zip" || rows[0]["Version"] != "23.01" || rows[0]["Source"] != "winget" {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
	if rows[1]["Name"] != "Microsoft Edge WebView2 Runtime" || rows[1]["Id"] != "Microsoft.EdgeWebView2Rt" {
		t.Fatalf("unexpected second row: %#v", rows[1])
	}
}

func TestParseWingetTableUpgradeList(t *testing.T) {
	rows := parseWingetTable(wingetUpgradeSample, []string{"Name", "Id", "Version", "Available", "Source"})
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(rows), rows)
	}
	if rows[0]["Name"] != "7-Zip 23.01" || rows[0]["Version"] != "23.01" || rows[0]["Available"] != "24.05" {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
	if rows[1]["Id"] != "Google.Chrome" || rows[1]["Available"] != "121.0.5" {
		t.Fatalf("unexpected second row: %#v", rows[1])
	}
}

func TestParseWingetTableNoHeaderReturnsNil(t *testing.T) {
	rows := parseWingetTable("No installed package found matching input criteria.\n", []string{"Name", "Id", "Version", "Source"})
	if rows != nil {
		t.Fatalf("expected nil for unparsable output, got %#v", rows)
	}
}

func TestParseWingetTableEmptyAfterHeaderIsNoRows(t *testing.T) {
	output := "Name    Id    Version    Source\n--------------------------------\n"
	rows := parseWingetTable(output, []string{"Name", "Id", "Version", "Source"})
	if len(rows) != 0 {
		t.Fatalf("expected zero rows, got %#v", rows)
	}
}
