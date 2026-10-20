package v2api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
)

const founderEmail = "founder@craveservices.my.id"

// consoleEnv memakai verifikasi login palsu: token → pengguna.
func (e *env) consoleEnv() {
	e.srv.BootstrapEmail = founderEmail
	e.srv.ConsoleAuth = func(_ context.Context, token string) (ConsoleUser, error) {
		switch token {
		case "tok-founder":
			return ConsoleUser{ID: "u-founder", Email: founderEmail}, nil
		case "tok-other":
			return ConsoleUser{ID: "u-other", Email: "dev@tokolain.id"}, nil
		}
		return ConsoleUser{}, errUnauthenticated
	}
}

func (e *env) console(token, path string, org ...string) (int, map[string]any) {
	e.t.Helper()
	h := map[string]string{"Authorization": "Bearer " + token}
	if len(org) > 0 {
		h["X-Org-Id"] = org[0]
	}
	return e.doH("GET", "/api/v2/console/"+path, h, nil)
}

func TestConsoleRequiresLogin(t *testing.T) {
	e := newEnv(t)
	e.consoleEnv()
	if code, _ := e.doH("GET", "/api/v2/console/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.console("tok-palsu", "me"); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}
	// secret key aplikasi bukan token console
	app := e.newAppKeys("POS")
	if code, _ := e.console(app.secret, "merchants"); code != http.StatusUnauthorized {
		t.Fatalf("api key must not open console: %d", code)
	}
}

func TestConsoleFounderBootstrap(t *testing.T) {
	e := newEnv(t)
	e.consoleEnv()

	// pengguna lain tidak otomatis mendapat org
	_, me := e.console("tok-other", "me")
	if orgs := me["orgs"].([]any); len(orgs) != 0 {
		t.Fatalf("non-founder must start without org: %v", me)
	}
	if code, out := e.console("tok-other", "merchants"); code != http.StatusForbidden || out["code"] != "NO_ORG" {
		t.Fatalf("no org: %d %v", code, out)
	}

	_, me = e.console("tok-founder", "me")
	orgs := me["orgs"].([]any)
	if len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "owner" || orgs[0].(map[string]any)["name"] != bootstrapOrgName {
		t.Fatalf("founder must own the bootstrap org: %v", me)
	}
	_, again := e.console("tok-founder", "me")
	if len(again["orgs"].([]any)) != 1 {
		t.Fatal("bootstrap must happen once")
	}
	m, _ := e.st.GetMerchant(context.Background(), "mch_777_88")
	if m.OrgID != orgs[0].(map[string]any)["id"] {
		t.Fatalf("existing merchant must be claimed by the founder org: %+v", m.OrgID)
	}
}

func TestConsoleReadsOnlyOwnOrg(t *testing.T) {
	e := newEnv(t)
	e.consoleEnv()
	ctx := context.Background()
	_, me := e.console("tok-founder", "me")
	founderOrg := me["orgs"].([]any)[0].(map[string]any)["id"].(string)

	// org lain dengan merchant & aplikasi sendiri
	_ = e.st.CreateOrg(ctx, ledger.Org{ID: "org_lain", Name: "Toko Lain"})
	_ = e.st.AddMember(ctx, ledger.Membership{OrgID: "org_lain", UserID: "u-other", Email: "dev@tokolain.id", Role: ledger.RoleDeveloper})
	_ = e.st.SaveMerchant(ctx, ledger.Merchant{ID: "mch_lain", Name: "Toko Lain", StaticQris: staticQris(t), Status: ledger.MerchantConnected, OrgID: "org_lain"})
	_ = e.st.CreateApp(ctx, ledger.App{ID: "app_lain", Name: "App Lain", MerchantID: "mch_lain"}, "hash-lain")

	mine := e.newAppKeys("Booking Lapangan")
	e.setWebhook(mine.id, "https://toko.id/hook")
	inv := e.invoice(mine.secret, "order-1", 25000)

	_, ms := e.console("tok-founder", "merchants")
	list := ms["merchants"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != "mch_777_88" {
		t.Fatalf("founder must see only own merchants: %v", ms)
	}
	if apps := list[0].(map[string]any)["apps"].([]any); len(apps) != 1 || apps[0].(map[string]any)["name"] != "Booking Lapangan" {
		t.Fatalf("merchant apps: %v", list[0])
	}

	_, as := e.console("tok-founder", "apps")
	raw, _ := json.Marshal(as)
	if bytes.Contains(raw, []byte("app_lain")) || bytes.Contains(raw, []byte("whsec_")) || bytes.Contains(raw, []byte(mine.secret)) ||
		bytes.Contains(raw, []byte("key_hash")) || bytes.Contains(raw, []byte("session")) {
		t.Fatalf("apps must not leak other orgs or secrets: %s", raw)
	}
	if a := as["apps"].([]any)[0].(map[string]any); a["client_key"] != mine.client || a["webhook_url"] != "https://toko.id/hook" {
		t.Fatalf("app view: %v", a)
	}

	_, is := e.console("tok-founder", "invoices")
	invs := is["invoices"].([]any)
	if len(invs) != 1 || invs[0].(map[string]any)["id"] != inv["id"] || invs[0].(map[string]any)["qris_string"] != nil {
		t.Fatalf("invoices: %v", is)
	}

	// org lain tidak bisa dipilih lewat X-Org-Id
	if code, _ := e.console("tok-founder", "merchants", "org_lain"); code != http.StatusForbidden {
		t.Fatalf("foreign org header: %d", code)
	}
	if code, _ := e.console("tok-other", "merchants", founderOrg); code != http.StatusForbidden {
		t.Fatalf("other user must not read founder org: %d", code)
	}
	_, other := e.console("tok-other", "merchants")
	if l := other["merchants"].([]any); len(l) != 1 || l[0].(map[string]any)["id"] != "mch_lain" {
		t.Fatalf("other org sees only its merchant: %v", other)
	}
}

func TestConsoleInvoiceWindow(t *testing.T) {
	e := newEnv(t)
	e.consoleEnv()
	e.console("tok-founder", "me")
	app := e.newAppKeys("POS")
	e.invoice(app.secret, "lama", 10000)
	e.clock = e.clock.Add(70 * 24 * time.Hour)
	e.invoice(app.secret, "baru", 20000)

	if _, out := e.console("tok-founder", "invoices"); len(out["invoices"].([]any)) != 1 || out["days"] != float64(60) {
		t.Fatalf("default 60 days: %v", out)
	}
	if _, out := e.console("tok-founder", "invoices?days=90"); len(out["invoices"].([]any)) != 2 {
		t.Fatalf("90 days: %v", out)
	}
	if _, out := e.console("tok-founder", "invoices?days=9999"); out["days"] != float64(60) {
		t.Fatalf("days out of range falls back: %v", out)
	}
}

func TestVerifySupabase(t *testing.T) {
	var hits int32
	supa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/auth/v1/user" || r.Header.Get("apikey") != "anon-key" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token-sah" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u-1", "email": "Founder@CraveServices.my.id"})
	}))
	defer supa.Close()

	s := &Server{SupabaseURL: supa.URL, SupabaseAnonKey: "anon-key"}
	u, err := s.verifySupabase(context.Background(), "token-sah")
	if err != nil || u.ID != "u-1" || u.Email != "founder@craveservices.my.id" {
		t.Fatalf("verify: %+v %v", u, err)
	}
	if _, err := s.verifySupabase(context.Background(), "token-sah"); err != nil || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("second call must hit the cache: hits=%d err=%v", hits, err)
	}
	if _, err := s.verifySupabase(context.Background(), "token-palsu"); err != errUnauthenticated {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := (&Server{}).verifySupabase(context.Background(), "x"); err == nil {
		t.Fatal("missing config must error")
	}
}
