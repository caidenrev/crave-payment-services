package v2api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hirotomasato/paygateme/core"
)

type fakeMailer struct{ sent []string }

func (f *fakeMailer) Send(_ context.Context, to []string, subject, _ string) error {
	f.sent = append(f.sent, strings.Join(to, ",")+"|"+subject)
	return nil
}

func lastUsed(t *testing.T, e *env, appID string) any {
	t.Helper()
	_, apps := e.console("tok-founder", "apps")
	for _, raw := range apps["apps"].([]any) {
		if a := raw.(map[string]any); a["id"] == appID {
			return a["last_used_at"]
		}
	}
	t.Fatalf("app %s not listed", appID)
	return nil
}

func TestAppLastUsed(t *testing.T) {
	e := newEnv(t)
	e.manageEnv()
	_, a, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Toko", "merchant_id": "mch_777_88"})
	key, appID := a["api_key"].(string), a["app"].(map[string]any)["id"].(string)
	if lastUsed(t, e, appID) != nil {
		t.Fatal("new app was never used")
	}
	first := e.clock
	e.do("GET", "/api/v2/merchant", key, nil)
	if got := lastUsed(t, e, appID); got != first.Format(time.RFC3339) {
		t.Fatalf("last used after first call: %v", got)
	}
	// dalam 1 menit tidak ditulis ulang, setelahnya diperbarui
	e.clock = first.Add(30 * time.Second)
	e.do("GET", "/api/v2/merchant", key, nil)
	if got := lastUsed(t, e, appID); got != first.Format(time.RFC3339) {
		t.Fatalf("throttled update: %v", got)
	}
	e.clock = first.Add(2 * time.Minute)
	e.do("GET", "/api/v2/merchant", key, nil)
	if got := lastUsed(t, e, appID); got != e.clock.Format(time.RFC3339) {
		t.Fatalf("updated after a minute: %v", got)
	}
	// key salah tidak menyentuh apa pun
	if code, _ := e.do("GET", "/api/v2/merchant", "pgk_salah", nil); code != http.StatusUnauthorized {
		t.Fatalf("bad key: %d", code)
	}
}

func TestMerchantExpiredEmailsOwners(t *testing.T) {
	e := newEnv(t)
	e.manageEnv()
	mail := &fakeMailer{}
	e.srv.Mail = mail
	_, a, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Toko", "merchant_id": "mch_777_88"})
	key := a["api_key"].(string)
	inv := e.invoice(key, "EXP-1", 15000)

	e.shop.recentErr = errors.New("unauthorized")
	e.shop.refreshErr = core.NewAuthError(core.CodeAuthRequired, "expired", nil)
	e.status(key, inv["id"].(string))
	if len(mail.sent) != 1 || !strings.HasPrefix(mail.sent[0], founderEmail+"|Kopi Senja terputus") {
		t.Fatalf("owner must be emailed once: %v", mail.sent)
	}
	// cek berikutnya: merchant sudah terputus, tidak ada email lagi
	e.status(key, inv["id"].(string))
	if len(mail.sent) != 1 {
		t.Fatalf("no repeated email: %v", mail.sent)
	}
}
