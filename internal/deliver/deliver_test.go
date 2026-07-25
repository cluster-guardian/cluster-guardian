package deliver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewValidates(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("expected error with no targets")
	}
	if _, err := New(Options{EmailTo: []string{"a@b.c"}}); err == nil {
		t.Error("expected error for email without SMTP config")
	}
	if _, err := New(Options{Dir: t.TempDir()}); err != nil {
		t.Errorf("dir-only target must be valid: %v", err)
	}
}

func TestDeliverDirAndWebhook(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		posted = string(b)
	}))
	defer srv.Close()

	dir := t.TempDir()
	d, err := New(Options{Dir: dir, WebhookURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	err = d.Deliver(context.Background(), Payload{
		Subject:    "weekly",
		HTMLBody:   []byte("<html>digest</html>"),
		JSON:       []byte(`{"cluster":"prod"}`),
		Attachment: &Attachment{Name: "report.pdf", MIME: "application/pdf", Data: []byte("%PDF-fake")},
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "report.pdf"))
	if err != nil || string(data) != "%PDF-fake" {
		t.Errorf("expected attachment written to dir, got %q, %v", data, err)
	}
	if posted != `{"cluster":"prod"}` {
		t.Errorf("expected JSON posted to webhook, got %q", posted)
	}
}

func TestDeliverEmail(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte
	d, err := New(Options{EmailTo: []string{"ops@example.com"}, SMTPHost: "mail:587", SMTPFrom: "guardian@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	d.sendMail = func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
		return nil
	}

	err = d.Deliver(context.Background(), Payload{
		Subject:    "weekly report",
		HTMLBody:   []byte("<html>digest</html>"),
		Attachment: &Attachment{Name: "report.pdf", MIME: "application/pdf", Data: []byte("%PDF-fake")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != "mail:587" || gotFrom != "guardian@example.com" || len(gotTo) != 1 {
		t.Errorf("unexpected SMTP call: %s %s %v", gotAddr, gotFrom, gotTo)
	}
	msg := string(gotMsg)
	for _, want := range []string{
		"Subject: weekly report",
		"To: ops@example.com",
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed",
		"Content-Type: text/html; charset=utf-8",
		`attachment; filename="report.pdf"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("email missing %q", want)
		}
	}
}

func TestDeliverJoinsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	dir := t.TempDir()
	d, err := New(Options{Dir: dir, WebhookURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = d.Deliver(context.Background(), Payload{HTMLBody: []byte("x"), JSON: []byte("{}")})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("expected webhook error surfaced, got %v", err)
	}
	// The dir target must still have been written despite the webhook error.
	files, _ := filepath.Glob(filepath.Join(dir, "digest-*.html"))
	if len(files) != 1 {
		t.Errorf("expected digest written despite webhook failure, got %v", files)
	}
}
