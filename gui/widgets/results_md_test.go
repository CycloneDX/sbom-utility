// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"testing"
)

// ── parseMarkdownSegments ─────────────────────────────────────────────────────

func TestParseMarkdownSegments_OnlyText(t *testing.T) {
	segs := parseMarkdownSegments("# Hello\nsome text")
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if segs[0].isTable {
		t.Fatal("expected text segment")
	}
}

func TestParseMarkdownSegments_OnlyTable(t *testing.T) {
	md := "| A | B |\n|---|---|\n| 1 | 2 |"
	segs := parseMarkdownSegments(md)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if !segs[0].isTable {
		t.Fatal("expected table segment")
	}
	if len(segs[0].rows) != 2 {
		t.Fatalf("expected 2 rows (header + data), got %d", len(segs[0].rows))
	}
}

func TestParseMarkdownSegments_TextThenTable(t *testing.T) {
	md := "# Title\n\n| A | B |\n|---|---|\n| 1 | 2 |"
	segs := parseMarkdownSegments(md)
	if len(segs) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segs))
	}
	if segs[0].isTable {
		t.Fatal("first segment should be text")
	}
	if !segs[1].isTable {
		t.Fatal("second segment should be table")
	}
}

func TestParseMarkdownSegments_TableThenText(t *testing.T) {
	md := "| A | B |\n|---|---|\n| 1 | 2 |\n\n### Footer"
	segs := parseMarkdownSegments(md)
	if len(segs) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segs))
	}
	if !segs[0].isTable {
		t.Fatal("first segment should be table")
	}
	if segs[1].isTable {
		t.Fatal("second segment should be text")
	}
}

func TestParseMarkdownSegments_SandwichedTable(t *testing.T) {
	md := "intro\n\n| H1 | H2 |\n|---|---|\n| v1 | v2 |\n\noutro"
	segs := parseMarkdownSegments(md)
	if len(segs) != 3 {
		t.Fatalf("expected 3 segments (text/table/text), got %d", len(segs))
	}
	if segs[0].isTable || !segs[1].isTable || segs[2].isTable {
		t.Fatal("expected text/table/text pattern")
	}
}

func TestParseMarkdownSegments_PipeyErrorMessage(t *testing.T) {
	// A line that starts with '|' but has no separator row must NOT be a table.
	md := "| some error message without separator"
	segs := parseMarkdownSegments(md)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if segs[0].isTable {
		t.Fatal("pipe-prefixed line without separator should be plain text, not a table")
	}
}

func TestParseMarkdownSegments_EmptyString(t *testing.T) {
	segs := parseMarkdownSegments("")
	if len(segs) != 0 {
		t.Fatalf("expected 0 segments for empty string, got %d", len(segs))
	}
}

func TestHasTableSeparator(t *testing.T) {
	withSep := []string{"| A | B |", "|---|---|", "| 1 | 2 |"}
	if !hasTableSeparator(withSep) {
		t.Fatal("expected separator to be found")
	}
	withoutSep := []string{"| A | B |", "| 1 | 2 |"}
	if hasTableSeparator(withoutSep) {
		t.Fatal("expected no separator")
	}
}

// ── isSeparatorRow ────────────────────────────────────────────────────────────

func TestIsSeparatorRow(t *testing.T) {
	cases := []struct {
		cells []string
		want  bool
	}{
		{[]string{"---", "---"}, true},
		{[]string{" :--- ", " ---: "}, true},
		{[]string{"---", "val"}, false},
		{[]string{"H1", "H2"}, false},
	}
	for _, tc := range cases {
		got := isSeparatorRow(tc.cells)
		if got != tc.want {
			t.Errorf("isSeparatorRow(%v) = %v, want %v", tc.cells, got, tc.want)
		}
	}
}

// ── splitTableRow ─────────────────────────────────────────────────────────────

func TestSplitTableRow(t *testing.T) {
	cells := splitTableRow("| foo | bar baz | qux |")
	want := []string{"foo", "bar baz", "qux"}
	if len(cells) != len(want) {
		t.Fatalf("expected %d cells, got %d", len(want), len(cells))
	}
	for i := range want {
		if cells[i] != want[i] {
			t.Errorf("cell[%d] = %q, want %q", i, cells[i], want[i])
		}
	}
}
