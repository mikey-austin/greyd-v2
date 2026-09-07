package spamdlist

import (
	"errors"
	"strings"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/blacklist"
)

func FuzzParseLimited(f *testing.F) {
	f.Add("192.168.20.0/24\n192.168.21.0 - 192.168.21.255\n# c\n192.168.23.1\n", 10)
	f.Add("1.2.3", 0)
	f.Add("300.1.1.1\n", 5)
	f.Add("1.1.1.1/33\n", 5)
	f.Add("", 1)
	f.Fuzz(func(t *testing.T, src string, limit int) {
		bl := blacklist.New("f", "m", blacklist.StorageList)
		err := ParseLimited(strings.NewReader(src), bl, blacklist.TypeBlack, limit)
		var perr *Error
		switch {
		case err == nil:
		case errors.Is(err, ErrTooManyEntries):
			if limit <= 0 {
				t.Fatal("limit error with no limit")
			}
		case errors.As(err, &perr):
		default:
			t.Fatalf("unexpected error %T: %v", err, err)
		}
		// Every entry records two boundaries; the cap holds when set.
		if limit > 0 && bl.Count > 2*limit {
			t.Fatalf("count %d exceeds limit %d", bl.Count, limit)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		sb.WriteString("10.")
		sb.WriteString(itoa(i / 256))
		sb.WriteString(".")
		sb.WriteString(itoa(i % 256))
		sb.WriteString(".0/24\n")
	}
	src := sb.String()
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		bl := blacklist.New("b", "m", blacklist.StorageList)
		if err := Parse(strings.NewReader(src), bl, blacklist.TypeBlack); err != nil {
			b.Fatal(err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
