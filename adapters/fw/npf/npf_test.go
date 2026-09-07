package npf

import (
	"strings"
	"testing"
)

func TestReplaceFileAndNames(t *testing.T) {
	if got := ReplaceFile([]string{"10.0.0.0/8", "", "192.0.2.1/32"}); got != "10.0.0.0/8\n192.0.2.1/32\n" {
		t.Fatalf("file %q", got)
	}
	if ReplaceFile(nil) != "" {
		t.Fatal("empty list must render nothing")
	}
	for name, ok := range map[string]bool{"greyd-whitelist": true, "a.b_c-1": true, "": false, "bad name": false, "x;y": false, strings.Repeat("x", 32): false} {
		if ValidTableName(name) != ok {
			t.Errorf("ValidTableName(%q) = %v", name, !ok)
		}
	}
}
