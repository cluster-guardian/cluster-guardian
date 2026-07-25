package teams

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "teams.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBothShapes(t *testing.T) {
	cfg, err := Load(write(t, `
teams:
  payments-team: [payments, checkout]
  platform-team:
    namespaces: [monitoring]
    notifyUrl: https://hooks.example.com/platform
`))
	if err != nil {
		t.Fatal(err)
	}
	for ns, want := range map[string]string{
		"payments":   "payments-team",
		"checkout":   "payments-team",
		"monitoring": "platform-team",
	} {
		if got := cfg.NamespaceTeam[ns]; got != want {
			t.Errorf("namespace %q: got team %q, want %q", ns, got, want)
		}
	}
	if cfg.NotifyURLs["platform-team"] != "https://hooks.example.com/platform" {
		t.Errorf("unexpected notify urls: %v", cfg.NotifyURLs)
	}
	if _, ok := cfg.NotifyURLs["payments-team"]; ok {
		t.Error("terse-form team must have no webhook")
	}
}

func TestLoadRejectsConflicts(t *testing.T) {
	_, err := Load(write(t, `
teams:
  a: [shared]
  b: [shared]
`))
	if err == nil {
		t.Error("expected error for a namespace owned by two teams")
	}

	if _, err := Load(write(t, "teams:\n  a: 42\n")); err == nil {
		t.Error("expected error for malformed team entry")
	}
}
