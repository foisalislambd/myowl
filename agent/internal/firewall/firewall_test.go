package firewall

import "testing"

func TestValidate(t *testing.T) {
	f := New(Options{Demo: true, Whitelist: []string{"203.0.113.0/24", "198.51.100.7"}})
	cases := []struct {
		ip, req string
		ok      bool
		want    string
	}{
		{"45.95.147.236", "1.2.3.4", true, "45.95.147.236"},
		{" 2001:db8::1 ", "", true, "2001:db8::1"},
		{"::ffff:45.95.147.236", "", true, "45.95.147.236"},
		{"not-an-ip", "", false, ""},
		{"127.0.0.1", "", false, ""},
		{"0.0.0.0", "", false, ""},
		{"10.0.0.5", "", false, ""},
		{"192.168.1.1", "", false, ""},
		{"1.2.3.4", "1.2.3.4", false, ""},
		{"203.0.113.50", "", false, ""},
		{"198.51.100.7", "", false, ""},
	}
	for _, c := range cases {
		got, err := f.Validate(c.ip, c.req)
		if (err == nil) != c.ok {
			t.Errorf("Validate(%q,%q) err=%v, want ok=%v", c.ip, c.req, err, c.ok)
		}
		if c.ok && got != c.want {
			t.Errorf("Validate(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
	p := New(Options{Demo: true, AllowPrivate: true})
	if _, err := p.Validate("10.0.0.5", ""); err != nil {
		t.Errorf("allow_private should permit 10.0.0.5: %v", err)
	}
}

func TestDemoBlockUnblock(t *testing.T) {
	f := New(Options{Demo: true})
	if !f.CanBlock() {
		t.Fatal("demo firewall should be able to block")
	}
	if s := f.Status(); s.Backend != "demo" || !s.CanBlock {
		t.Fatalf("unexpected status %+v", s)
	}
}
