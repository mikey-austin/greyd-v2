package activation

import "golang.org/x/sys/unix"

func dup2(from, to int) error { return unix.Dup3(from, to, 0) }
