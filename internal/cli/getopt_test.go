package cli

import (
	"errors"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	opts, rest, err := Parse("adtTDf:Y:", []string{"-a", "-tT", "-f", "x.conf", "-Yhost1", "-Y", "host2", "--", "1.2.3.4", "-d"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Opt{{'a', ""}, {'t', ""}, {'T', ""}, {'f', "x.conf"}, {'Y', "host1"}, {'Y', "host2"}}
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf("opts %+v", opts)
	}
	if !reflect.DeepEqual(rest, []string{"1.2.3.4", "-d"}) {
		t.Fatalf("rest %v", rest)
	}

	// Positional arguments end option parsing.
	opts, rest, err = Parse("ab", []string{"-a", "key", "-b"})
	if err != nil || len(opts) != 1 || !reflect.DeepEqual(rest, []string{"key", "-b"}) {
		t.Fatalf("positional: %+v %v %v", opts, rest, err)
	}

	// A bundled option with an argument consumes the remainder.
	opts, _, err = Parse("dW:", []string{"-dW2"})
	if err != nil || !reflect.DeepEqual(opts, []Opt{{'d', ""}, {'W', "2"}}) {
		t.Fatalf("bundled: %+v %v", opts, err)
	}
	if n, err := opts[1].Int(); err != nil || n != 2 {
		t.Fatalf("Int: %d %v", n, err)
	}
	if _, err := (Opt{Flag: 'W', Arg: "x"}).Int(); !errors.Is(err, ErrUsage) {
		t.Fatal("bad int must be a usage error")
	}

	_, _, err = Parse("a", []string{"-x"})
	var ue *UnknownOptionError
	if !errors.As(err, &ue) || ue.Flag != 'x' || !errors.Is(err, ErrUsage) {
		t.Fatalf("unknown: %v", err)
	}
	_, _, err = Parse("f:", []string{"-f"})
	var me *MissingArgError
	if !errors.As(err, &me) || me.Flag != 'f' || !errors.Is(err, ErrUsage) {
		t.Fatalf("missing: %v", err)
	}
	if opts, rest, err := Parse("a", nil); err != nil || opts != nil || len(rest) != 0 {
		t.Fatal("empty args")
	}
	if _, rest, _ := Parse("a", []string{"-", "x"}); !reflect.DeepEqual(rest, []string{"-", "x"}) {
		t.Fatal("lone dash is positional")
	}
}
