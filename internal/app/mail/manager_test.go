package mail

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/h44z/wg-portal/internal/config"
	"github.com/h44z/wg-portal/internal/domain"
)

type sentMail struct {
	subject string
	body    string
	to      []string
	options domain.MailOptions
}

type recordingMailer struct {
	sent []sentMail
	err  error
}

func (m *recordingMailer) Send(
	_ context.Context,
	subject string,
	body string,
	to []string,
	options *domain.MailOptions,
) error {
	m.sent = append(m.sent, sentMail{
		subject: subject,
		body:    body,
		to:      to,
		options: *options,
	})
	return m.err
}

type stubUserRepo struct {
	user *domain.User
	err  error
}

func (r *stubUserRepo) GetUser(_ context.Context, _ domain.UserIdentifier) (*domain.User, error) {
	return r.user, r.err
}

func Test_base64UrlEncode_isReversibleWithHandlerDecode(t *testing.T) {
	inputs := []string{
		"peer-identifier",
		"aGVsbG8=",    // ensure padding characters are handled
		"abc/def+ghi", // ensure + and / are handled
		"wgTestKey1234567890==",
	}

	for _, in := range inputs {
		encoded := domain.Base64UrlEncode(in)

		// The URL-safe variant must not contain characters that are unsafe in URLs.
		if strings.ContainsAny(encoded, "+/=") {
			t.Fatalf("encoded value %q still contains unsafe characters", encoded)
		}

		decoded := domain.Base64UrlDecode(encoded)
		if decoded != in {
			t.Fatalf("round trip failed: got %q, want %q (encoded: %q)", decoded, in, encoded)
		}
	}
}

func Test_getPeerConfigDownloadLink(t *testing.T) {
	tests := []struct {
		name        string
		externalUrl string
		basePath    string
		peerId      domain.PeerIdentifier
		style       string
		want        string
	}{
		{
			name:        "no base path",
			externalUrl: "https://wg.example.com",
			basePath:    "",
			peerId:      "peer1",
			style:       "wgquick",
			want:        "https://wg.example.com/app/#/peer/config/" + domain.Base64UrlEncode("peer1") + "?style=wgquick",
		},
		{
			name:        "with base path",
			externalUrl: "https://wg.example.com",
			basePath:    "/wg",
			peerId:      "peer1",
			style:       "",
			want:        "https://wg.example.com/wg/app/#/peer/config/" + domain.Base64UrlEncode("peer1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Web.ExternalUrl = tt.externalUrl
			cfg.Web.BasePath = tt.basePath
			m := Manager{cfg: cfg}

			got := m.getPeerConfigDownloadLink(tt.peerId, tt.style)
			if got != tt.want {
				t.Fatalf("getPeerConfigDownloadLink() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_GetConfigMail_containsLink(t *testing.T) {
	handler, err := newTemplateHandler("https://wg.example.com", "WireGuard Portal", "")
	if err != nil {
		t.Fatalf("failed to create template handler: %v", err)
	}

	link := "https://wg.example.com/app/#/peer/config/abc?style=wgquick"
	txtReader, htmlReader, err := handler.GetConfigMail(&domain.User{Firstname: "John", Lastname: "Doe"}, link)
	if err != nil {
		t.Fatalf("failed to render link mail: %v", err)
	}

	txt, _ := io.ReadAll(txtReader)
	html, _ := io.ReadAll(htmlReader)

	if !strings.Contains(string(txt), link) {
		t.Errorf("text link mail does not contain the generated link.\n%s", string(txt))
	}
	if !strings.Contains(string(html), link) {
		t.Errorf("html link mail does not contain the generated link.\n%s", string(html))
	}

	// The link mail must not reference the placeholder that was used before the fix.
	if strings.Contains(string(txt), "deep link TBD") || strings.Contains(string(html), "deep link TBD") {
		t.Errorf("link mail still contains the placeholder link")
	}
}

func TestAttemptPeerExpiryWarning_SendsWarningToLinkedUser(t *testing.T) {
	cfg := &config.Config{}
	cfg.Web.ExternalUrl = "https://wg.example.com"
	cfg.Web.SiteTitle = "Example VPN"
	mailer := &recordingMailer{}
	m := Manager{
		cfg:    cfg,
		mailer: mailer,
		users: &stubUserRepo{user: &domain.User{
			Email: "owner@example.com",
		}},
	}
	expiresAt := time.Date(2030, time.July, 2, 15, 4, 0, 0, time.UTC)
	peer := &domain.Peer{
		Identifier:     "peer-key",
		DisplayName:    "Laptop",
		UserIdentifier: "owner",
		ExpiresAt:      &expiresAt,
	}

	err := m.AttemptPeerExpiryWarning(context.Background(), peer)

	if err != nil {
		t.Fatalf("AttemptPeerExpiryWarning returned error: %v", err)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(mailer.sent))
	}
	got := mailer.sent[0]
	if got.subject != "Develer VPN expiration warning" {
		t.Errorf("unexpected subject %q", got.subject)
	}
	if len(got.to) != 1 || got.to[0] != "owner@example.com" {
		t.Errorf("unexpected recipients %v", got.to)
	}
	for _, want := range []string{"Develer VPN", "Laptop", "02 Jul 2030 17:04 CEST", "https://wg.example.com"} {
		if !strings.Contains(got.body, want) {
			t.Errorf("text body does not contain %q:\n%s", want, got.body)
		}
		if !strings.Contains(got.options.HtmlBody, want) {
			t.Errorf("HTML body does not contain %q:\n%s", want, got.options.HtmlBody)
		}
	}
	if strings.Contains(got.body, "peer-key") || strings.Contains(got.options.HtmlBody, "peer-key") {
		t.Errorf("email must not contain the peer public key")
	}
}

func TestAttemptPeerExpiryWarning_UsesPeerEmailFallback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Mail.AllowPeerEmail = true
	mailer := &recordingMailer{}
	m := Manager{
		cfg:    cfg,
		mailer: mailer,
		users:  &stubUserRepo{err: domain.ErrNotFound},
	}
	expiresAt := time.Now().Add(6 * 24 * time.Hour)
	peer := &domain.Peer{
		Identifier:     "peer-key",
		UserIdentifier: "owner@example.com",
		ExpiresAt:      &expiresAt,
	}

	err := m.AttemptPeerExpiryWarning(context.Background(), peer)

	if err != nil {
		t.Fatalf("AttemptPeerExpiryWarning returned error: %v", err)
	}
	if len(mailer.sent) != 1 || len(mailer.sent[0].to) != 1 ||
		mailer.sent[0].to[0] != "owner@example.com" {
		t.Fatalf("expected fallback recipient owner@example.com, got %+v", mailer.sent)
	}
	got := mailer.sent[0]
	if !strings.Contains(got.body, "Unnamed peer") ||
		strings.Contains(got.body, "peer-key") ||
		strings.Contains(got.options.HtmlBody, "peer-key") {
		t.Errorf("unnamed-peer email must use a generic label without the public key")
	}
}

func TestAttemptPeerExpiryWarning_SkipsMissingRecipient(t *testing.T) {
	cfg := &config.Config{}
	mailer := &recordingMailer{}
	m := Manager{
		cfg:    cfg,
		mailer: mailer,
		users:  &stubUserRepo{err: domain.ErrNotFound},
	}
	expiresAt := time.Now().Add(6 * 24 * time.Hour)
	peer := &domain.Peer{
		Identifier:     "peer-key",
		UserIdentifier: "owner",
		ExpiresAt:      &expiresAt,
	}

	err := m.AttemptPeerExpiryWarning(context.Background(), peer)

	if err != nil {
		t.Fatalf("AttemptPeerExpiryWarning returned error: %v", err)
	}
	if len(mailer.sent) != 0 {
		t.Fatalf("expected no email, got %d", len(mailer.sent))
	}
}

func TestAttemptPeerExpiryWarning_ReturnsSmtpFailure(t *testing.T) {
	cfg := &config.Config{}
	smtpErr := errors.New("smtp unavailable")
	mailer := &recordingMailer{err: smtpErr}
	m := Manager{
		cfg:    cfg,
		mailer: mailer,
		users: &stubUserRepo{user: &domain.User{
			Email: "owner@example.com",
		}},
	}
	expiresAt := time.Now().Add(6 * 24 * time.Hour)
	peer := &domain.Peer{
		Identifier:     "peer-key",
		UserIdentifier: "owner",
		ExpiresAt:      &expiresAt,
	}

	err := m.AttemptPeerExpiryWarning(context.Background(), peer)

	if !errors.Is(err, smtpErr) {
		t.Fatalf("expected SMTP failure, got %v", err)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("expected 1 delivery attempt, got %d", len(mailer.sent))
	}
}
