package redirects

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseLinesNormalizesAndDeduplicates(t *testing.T) {
	t.Parallel()

	input := `
# comment
example.com
0.0.0.0 example.com
127.0.0.1 keep.local # inline comment
bad.example other.example
`

	got, err := ParseLines(input)
	if err != nil {
		t.Fatalf("ParseLines returned error: %v", err)
	}

	want := []string{
		"0.0.0.0 example.com",
		"127.0.0.1 keep.local",
		"0.0.0.0 bad.example other.example",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected lines\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestBuildManagedContentAppendsOnlyMissingEntries(t *testing.T) {
	t.Parallel()

	redirects := []string{"0.0.0.0 one.test", "0.0.0.0 two.test"}
	begin := "# >>> block >>>"
	end := "# <<< block <<<"

	appended, err := BuildManagedContent("127.0.0.1 localhost\n", redirects, begin, end)
	if err != nil {
		t.Fatalf("BuildManagedContent append returned error: %v", err)
	}

	expectedAppend := "127.0.0.1 localhost\n\n# >>> block >>>\n0.0.0.0 one.test\n0.0.0.0 two.test\n# <<< block <<<\n"
	if appended != expectedAppend {
		t.Fatalf("unexpected appended content\nwant:\n%s\ngot:\n%s", expectedAppend, appended)
	}

	unchanged, err := BuildManagedContent(appended, redirects, begin, end)
	if err != nil {
		t.Fatalf("BuildManagedContent unchanged returned error: %v", err)
	}
	if unchanged != appended {
		t.Fatalf("expected existing content to stay unchanged\nwant:\n%s\ngot:\n%s", appended, unchanged)
	}

	withExtraHost := expectedAppend + "\n192.168.0.10 intranet.local\n"
	updated, err := BuildManagedContent(withExtraHost, []string{"0.0.0.0 one.test", "0.0.0.0 three.test"}, begin, end)
	if err != nil {
		t.Fatalf("BuildManagedContent update returned error: %v", err)
	}

	expectedUpdate := "127.0.0.1 localhost\n\n# >>> block >>>\n0.0.0.0 one.test\n0.0.0.0 two.test\n0.0.0.0 three.test\n# <<< block <<<\n\n192.168.0.10 intranet.local\n"
	if updated != expectedUpdate {
		t.Fatalf("unexpected updated content\nwant:\n%s\ngot:\n%s", expectedUpdate, updated)
	}
}

func TestLoadSourcesReadsLineBreakSeparatedURLs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "env.json")
	content := []byte("{\"sources\":\"https://one.test/list.txt\\nhttps://two.test/list.txt\"}")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	got, err := LoadSources(path)
	if err != nil {
		t.Fatalf("LoadSources returned error: %v", err)
	}

	want := []string{"https://one.test/list.txt", "https://two.test/list.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected sources\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestLoadSourcesReadsJSONArray(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "env.json")
	content := []byte("{\"sources\":[\"https://one.test/list.txt\",\"https://two.test/list.txt\"]}")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	got, err := LoadSources(path)
	if err != nil {
		t.Fatalf("LoadSources returned error: %v", err)
	}

	want := []string{"https://one.test/list.txt", "https://two.test/list.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected sources\nwant: %#v\ngot:  %#v", want, got)
	}
}
