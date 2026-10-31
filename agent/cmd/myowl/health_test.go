package main

import "testing"

func TestHealthURL(t *testing.T) {
	cases := []struct {
		listen string
		tls    bool
		want   string
	}{
		{"0.0.0.0:8787", false, "http://127.0.0.1:8787/api/auth/status"},
		{":9000", false, "http://127.0.0.1:9000/api/auth/status"},
		{"127.0.0.1:8787", true, "https://127.0.0.1:8787/api/auth/status"},
		{"[::]:8787", false, "http://127.0.0.1:8787/api/auth/status"},
		{"[::1]:8787", false, "http://[::1]:8787/api/auth/status"},
		{"bogus", false, "http://127.0.0.1:8787/api/auth/status"},
	}
	for _, c := range cases {
		if got := healthURL(c.listen, c.tls); got != c.want {
			t.Errorf("healthURL(%q,%v) = %q, want %q", c.listen, c.tls, got, c.want)
		}
	}
}
