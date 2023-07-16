package main

import "testing"

func TestHello(t *testing.T) {
	got := Hello("steffano")
	want := "Hello, steffano"

	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
