package kv

import (
	"math"
	"testing"

	"github.com/mikey-austin/greyd-v2/internal/core"
)

// TestCodecRoundTripProperty encodes and decodes keys and data across the
// value ranges the greylister produces.
func TestCodecRoundTripProperty(t *testing.T) {
	// Keys are NUL separated like the C Berkeley DB format, so a NUL inside
	// a field is not representable; the SMTP reader truncates lines at the
	// first NUL, as C strings did.
	strs := []string{"", "a", "1.2.3.4", "2001:db8::1", "user@example.org", "with space", "\xff\xfe", "tab\tsep"}
	for _, s := range strs {
		for _, k := range []core.Key{core.IPKey(s), core.MailKey(s), core.DomainKey(s)} {
			got, err := DecodeKey(EncodeKey(k))
			if err != nil || got != k {
				t.Fatalf("key %+v: got %+v err %v", k, got, err)
			}
		}
		for _, s2 := range strs {
			k := core.TupleKey(core.Tuple{IP: s, Helo: s2, From: s2, To: s})
			got, err := DecodeKey(EncodeKey(k))
			if err != nil || got != k {
				t.Fatalf("tuple %+v: got %+v err %v", k, got, err)
			}
		}
	}
	ints := []int64{0, 1, -1, 42, math.MaxInt32, math.MinInt32, math.MaxInt64, math.MinInt64}
	for _, a := range ints {
		for _, b := range ints {
			d := core.Data{First: a, Pass: b, Expire: a ^ b, BCount: int(a % 1000), PCount: int(b % 1000)}
			got, err := DecodeData(EncodeData(d))
			if err != nil || got != d {
				t.Fatalf("data %+v: got %+v err %v", d, got, err)
			}
		}
	}
}

func FuzzDecodeKey(f *testing.F) {
	f.Add(EncodeKey(core.IPKey("1.2.3.4")))
	f.Add(EncodeKey(core.TupleKey(core.Tuple{IP: "1.2.3.4", Helo: "h", From: "f", To: "t"})))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := DecodeKey(b)
		if err != nil {
			return
		}
		again, err := DecodeKey(EncodeKey(k))
		if err != nil || again != k {
			t.Fatalf("re-encoding %+v: %+v %v", k, again, err)
		}
	})
}

func FuzzDecodeData(f *testing.F) {
	f.Add(EncodeData(core.Data{First: 1, Pass: 2, Expire: 3, BCount: 4, PCount: -1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeData(b)
		if err != nil {
			return
		}
		again, err := DecodeData(EncodeData(d))
		if err != nil || again != d {
			t.Fatalf("re-encoding %+v: %+v %v", d, again, err)
		}
	})
}
