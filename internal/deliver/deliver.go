// Package deliver sends rendered reports to configured targets: SMTP email,
// a webhook POST, and files in a directory for pull-based workflows.
package deliver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Attachment is a file attached to an email or written to the directory.
type Attachment struct {
	Name string
	MIME string
	Data []byte
}

// Payload is one scheduled report ready for delivery.
type Payload struct {
	Subject    string
	HTMLBody   []byte // digest page; email body and dir fallback
	JSON       []byte // webhook body
	Attachment *Attachment
}

// Options configure the delivery targets; empty targets are skipped.
type Options struct {
	EmailTo  []string
	SMTPHost string // host:port
	SMTPFrom string
	// SMTP credentials come from SMTP_USERNAME / SMTP_PASSWORD; empty means
	// unauthenticated SMTP.
	WebhookURL string
	Dir        string
}

// Deliverer fans a payload out to every configured target.
type Deliverer struct {
	opts   Options
	client *http.Client
	// sendMail is swappable for tests.
	sendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// New validates the target configuration.
func New(opts Options) (*Deliverer, error) {
	if len(opts.EmailTo) > 0 && (opts.SMTPHost == "" || opts.SMTPFrom == "") {
		return nil, errors.New("email delivery needs --report-smtp-host and --report-smtp-from")
	}
	if len(opts.EmailTo) == 0 && opts.WebhookURL == "" && opts.Dir == "" {
		return nil, errors.New("no delivery target configured (email, webhook, or directory)")
	}
	return &Deliverer{
		opts:     opts,
		client:   &http.Client{Timeout: 30 * time.Second},
		sendMail: smtp.SendMail,
	}, nil
}

// Deliver sends the payload to every configured target and joins the errors,
// so one failing target never blocks the others.
func (d *Deliverer) Deliver(ctx context.Context, p Payload) error {
	var errs []error
	if d.opts.Dir != "" {
		if err := d.writeDir(p); err != nil {
			errs = append(errs, fmt.Errorf("dir: %w", err))
		}
	}
	if d.opts.WebhookURL != "" && len(p.JSON) > 0 {
		if err := d.postWebhook(ctx, p.JSON); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	if len(d.opts.EmailTo) > 0 {
		if err := d.email(p); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (d *Deliverer) writeDir(p Payload) error {
	if err := os.MkdirAll(d.opts.Dir, 0o755); err != nil {
		return err
	}
	if p.Attachment != nil {
		return os.WriteFile(filepath.Join(d.opts.Dir, p.Attachment.Name), p.Attachment.Data, 0o644)
	}
	name := "digest-" + time.Now().UTC().Format("20060102T150405Z") + ".html"
	return os.WriteFile(filepath.Join(d.opts.Dir, name), p.HTMLBody, 0o644)
}

func (d *Deliverer) postWebhook(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.opts.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *Deliverer) email(p Payload) error {
	msg, err := buildEmail(d.opts.SMTPFrom, d.opts.EmailTo, p.Subject, p.HTMLBody, p.Attachment)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if user := os.Getenv("SMTP_USERNAME"); user != "" {
		host := d.opts.SMTPHost
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		auth = smtp.PlainAuth("", user, os.Getenv("SMTP_PASSWORD"), host)
	}
	return d.sendMail(d.opts.SMTPHost, auth, d.opts.SMTPFrom, d.opts.EmailTo, msg)
}

// buildEmail assembles a multipart/mixed MIME message: HTML body plus an
// optional base64 attachment.
func buildEmail(from string, to []string, subject string, htmlBody []byte, att *Attachment) ([]byte, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary())

	body, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeBase64(body, htmlBody); err != nil {
		return nil, err
	}

	if att != nil {
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {att.MIME},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", att.Name)},
		})
		if err != nil {
			return nil, err
		}
		if err := writeBase64(part, att.Data); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeBase64 writes data base64-encoded in RFC 2045 76-column lines.
func writeBase64(w io.Writer, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 0 {
		n := min(76, len(encoded))
		if _, err := w.Write([]byte(encoded[:n] + "\r\n")); err != nil {
			return err
		}
		encoded = encoded[n:]
	}
	return nil
}
