package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingUsesDefaults(t *testing.T) {
	c, missing, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil || !missing {
		t.Fatalf("missing=%v err=%v", missing, err)
	}
	if c.Listen != "0.0.0.0:8787" || c.Retention.Days != 14 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestLoadExample(t *testing.T) {
	b, err := os.ReadFile("../../cmd/myowl/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte(strings.Replace(string(b), `listen: "0.0.0.0:8787"`, `listen: "127.0.0.1:9000"`, 1)), 0o600)
	c, missing, err := Load(p)
	if err != nil || missing {
		t.Fatalf("load example: %v", err)
	}
	if c.Listen != "127.0.0.1:9000" || len(c.AccessLogs) == 0 || c.Detection.SSHFailThreshold != 5 {
		t.Fatalf("unexpected: listen=%s logs=%d", c.Listen, len(c.AccessLogs))
	}
	if c.TLSEnabled() {
		t.Fatal("tls should be off")
	}
}

func TestLoadInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(p, []byte("listen: [oops"), 0o600)
	if _, _, err := Load(p); err == nil {
		t.Fatal("expected parse error")
	}
}
