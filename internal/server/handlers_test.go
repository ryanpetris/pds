package server

import (
	"os"
	"testing"
)

// A negative offset must not panic the directory-list adapter.
func TestListerAtNegativeOffset(t *testing.T) {
	l := listerat{vinfo{name: "a"}, vinfo{name: "b"}}
	buf := make([]os.FileInfo, 2)
	if _, err := l.ListAt(buf, -1); err == nil {
		t.Fatalf("negative offset should return an error")
	}
}

func TestListerAtNormal(t *testing.T) {
	l := listerat{vinfo{name: "a"}, vinfo{name: "b"}, vinfo{name: "c"}}
	buf := make([]os.FileInfo, 2)
	n, err := l.ListAt(buf, 0)
	if err != nil || n != 2 {
		t.Fatalf("ListAt(0) = %d, %v; want 2, nil", n, err)
	}
	n, err = l.ListAt(buf, 2)
	if n != 1 || err == nil { // last element, EOF
		t.Fatalf("ListAt(2) = %d, %v; want 1, io.EOF", n, err)
	}
}
