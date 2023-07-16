package main

import "testing"

func TestHello(t *testing.T) {
	t.Run("saying hello to peoplle", func(t *testing.T) {
		got := Hello("steffano", "")
		want := "Hello, steffano"
		assertCorrectMessage(t, got, want)
	})
	t.Run("say 'Hello, World' when an empty string is supplied", func(t *testing.T) {
		got := Hello("", "")
		want := "Hello, World"
		assertCorrectMessage(t, got, want)
	})
	t.Run("in Spanish", func(t *testing.T) {
		got := Hello("Steffano", "Spanish")
		want := "Hola, Steffano"
		assertCorrectMessage(t, got, want)

	})
	t.Run("in French", func(t *testing.T) {
		got := Hello("Steffano", "French")
		want := "Bonjour, Steffano"
		assertCorrectMessage(t, got, want)

	})

}

func assertCorrectMessage(t testing.TB, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
