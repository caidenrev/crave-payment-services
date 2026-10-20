package v2api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/shopee"
)

// fakeLogin meniru login OTP Shopee Partner.
//
//	123456 → merchant 999 / store 55        222222 → harus pilih merchant (901, 902)
//	777888 → merchant 777 / store 88 (sudah milik org founder)   lainnya → kode salah
type fakeLogin struct{}

func (fakeLogin) RequestOtp(_ context.Context, phone, _ string, channel int) (*shopee.OtpChallenge, error) {
	if phone == "0000" {
		return nil, errors.New("nomor tidak terdaftar")
	}
	return &shopee.OtpChallenge{PhoneNumber: "+6281234567890", Channel: channel, RiskToken: "rahasia-risk-token"}, nil
}

func (fakeLogin) VerifyOtp(_ context.Context, ch shopee.OtpChallenge, otp string) (*shopee.Session, *shopee.OtpVerification, error) {
	if ch.RiskToken != "rahasia-risk-token" {
		return nil, nil, errors.New("challenge rusak")
	}
	switch otp {
	case "123456":
		return &shopee.Session{Merchant: shopee.MerchantSummary{ID: "999", Name: "Toko Baru"}, StoreID: "55"}, nil, nil
	case "777888":
		return &shopee.Session{Merchant: shopee.MerchantSummary{ID: "777", Name: "Kopi Senja"}, StoreID: "88"}, nil, nil
	case "222222":
		return nil, &shopee.OtpVerification{TocNonce: "nonce", Merchants: []shopee.MerchantSummary{{ID: "901", Name: "Cabang A"}, {ID: "902", Name: "Cabang B"}}}, nil
	}
	return nil, nil, errors.New("kode OTP salah")
}

func (fakeLogin) Complete(_ context.Context, v shopee.OtpVerification, merchantID, _ string) (*shopee.Session, error) {
	if v.TocNonce != "nonce" {
		return nil, errors.New("verification rusak")
	}
	return &shopee.Session{Merchant: shopee.MerchantSummary{ID: merchantID, Name: "Pilihan " + merchantID}, StoreID: "1"}, nil
}

// consoleCall memanggil endpoint console dengan metode & body bebas.
func (e *env) consoleCall(method, token, path string, body any, org ...string) (int, map[string]any, string) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/api/v2/console/"+path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	if len(org) > 0 {
		req.Header.Set("X-Org-Id", org[0])
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// manageEnv: founder (owner org bootstrap), plus org lain berisi pengguna tok-other (owner).
func (e *env) manageEnv() (founderOrg string) {
	e.consoleEnv()
	e.srv.Login = fakeLogin{}
	e.srv.AllowInsecureWebhooks = true
	_, me := e.console("tok-founder", "me")
	ctx := context.Background()
	_ = e.st.CreateOrg(ctx, ledger.Org{ID: "org_lain", Name: "Toko Lain"})
	_ = e.st.AddMember(ctx, ledger.Membership{OrgID: "org_lain", UserID: "u-other", Email: "dev@tokolain.id", Role: ledger.RoleOwner})
	return me["orgs"].([]any)[0].(map[string]any)["id"].(string)
}

func (e *env) otpRequest(token string) string {
	e.t.Helper()
	code, out, raw := e.consoleCall("POST", token, "merchants/otp/request", map[string]any{"phone": "081234567890", "password": "rahasia-shopee", "channel": 3})
	if code != http.StatusOK {
		e.t.Fatalf("otp request: %d %s", code, raw)
	}
	if strings.Contains(raw, "rahasia-risk-token") || strings.Contains(raw, "rahasia-shopee") {
		e.t.Fatalf("otp request must not leak Shopee state or password: %s", raw)
	}
	if out["phone"] != "••••7890" {
		e.t.Fatalf("phone must be masked: %v", out)
	}
	return out["challenge_id"].(string)
}

func TestConsoleConnectMerchantOTP(t *testing.T) {
	e := newEnv(t)
	founderOrg := e.manageEnv()

	id := e.otpRequest("tok-founder")
	// kode salah: dapat challenge baru, yang lama tidak bisa dipakai lagi
	code, out, _ := e.consoleCall("POST", "tok-founder", "merchants/otp/verify", map[string]any{"challenge_id": id, "otp": "000000"})
	retry, _ := out["challenge_id"].(string)
	if code != http.StatusBadRequest || retry == "" || retry == id || out["attempts_left"] != float64(2) {
		t.Fatalf("wrong otp must allow a retry: %d %v", code, out)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "merchants/otp/verify", map[string]any{"challenge_id": id, "otp": "123456"}); code != http.StatusGone {
		t.Fatalf("used challenge must be rejected: %d", code)
	}
	// QRIS tidak valid ditolak sebelum OTP dipakai
	if code, _, _ := e.consoleCall("POST", "tok-founder", "merchants/otp/verify", map[string]any{"challenge_id": retry, "otp": "123456", "static_qris": "bukan-qris"}); code != http.StatusBadRequest {
		t.Fatalf("invalid static qris: %d", code)
	}
	code, out, _ = e.consoleCall("POST", "tok-founder", "merchants/otp/verify", map[string]any{"challenge_id": retry, "otp": "123456", "static_qris": staticQris(t)})
	if code != http.StatusOK || out["status"] != "CONNECTED" {
		t.Fatalf("connect: %d %v", code, out)
	}
	m, err := e.st.GetMerchant(context.Background(), "mch_999_55")
	if err != nil || m.OrgID != founderOrg || m.StaticQris == "" || m.Status != ledger.MerchantConnected {
		t.Fatalf("merchant must belong to the founder org with QRIS: %+v %v", m, err)
	}
	_, list := e.console("tok-founder", "merchants")
	if len(list["merchants"].([]any)) != 2 {
		t.Fatalf("founder now has two merchants: %v", list)
	}
}

func TestConsoleConnectMerchantSelection(t *testing.T) {
	e := newEnv(t)
	founderOrg := e.manageEnv()
	id := e.otpRequest("tok-founder")
	code, out, raw := e.consoleCall("POST", "tok-founder", "merchants/otp/verify", map[string]any{"challenge_id": id, "otp": "222222"})
	if code != http.StatusOK || out["status"] != "MERCHANT_SELECTION_NEEDED" || len(out["merchants"].([]any)) != 2 || strings.Contains(raw, "nonce") {
		t.Fatalf("selection: %d %s", code, raw)
	}
	vid := out["verification_id"].(string)
	if code, _, _ := e.consoleCall("POST", "tok-other", "merchants/otp/complete", map[string]any{"verification_id": vid, "merchant_id": "902"}); code != http.StatusGone {
		t.Fatalf("another user must not use this verification: %d", code)
	}
	code, out, _ = e.consoleCall("POST", "tok-founder", "merchants/otp/complete", map[string]any{"verification_id": vid, "merchant_id": "902"})
	if code != http.StatusOK || out["status"] != "CONNECTED" {
		t.Fatalf("complete: %d %v", code, out)
	}
	if m, _ := e.st.GetMerchant(context.Background(), "mch_902_1"); m.OrgID != founderOrg {
		t.Fatalf("selected merchant must belong to the org: %+v", m)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "merchants/otp/complete", map[string]any{"verification_id": vid, "merchant_id": "901"}); code != http.StatusGone {
		t.Fatalf("verification is single use: %d", code)
	}
}

func TestConsoleConnectRejectsForeignMerchant(t *testing.T) {
	e := newEnv(t)
	founderOrg := e.manageEnv()
	// mch_777_88 sudah diklaim org founder saat bootstrap; org lain mencoba login merchant yang sama
	id := e.otpRequest("tok-other")
	code, out, _ := e.consoleCall("POST", "tok-other", "merchants/otp/verify", map[string]any{"challenge_id": id, "otp": "777888"})
	if code != http.StatusConflict || out["code"] != "MERCHANT_OWNED" {
		t.Fatalf("foreign merchant must be refused: %d %v", code, out)
	}
	if m, _ := e.st.GetMerchant(context.Background(), "mch_777_88"); m.OrgID != founderOrg {
		t.Fatalf("ownership must not change: %+v", m.OrgID)
	}
	// static QRIS merchant org lain juga tidak bisa diubah
	if code, _, _ := e.consoleCall("PUT", "tok-other", "merchants/mch_777_88/static-qris", map[string]any{"static_qris": staticQris(t)}); code != http.StatusNotFound {
		t.Fatalf("foreign static qris: %d", code)
	}
}

func TestConsoleOtpRateLimitAndRoles(t *testing.T) {
	e := newEnv(t)
	founderOrg := e.manageEnv()
	for i := 0; i < otpRateMax; i++ {
		e.otpRequest("tok-founder")
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "merchants/otp/request", map[string]any{"phone": "0812", "password": "x"}); code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", code)
	}
	if code, out, _ := e.consoleCall("POST", "tok-other", "merchants/otp/request", map[string]any{"phone": "0000", "password": "x"}); code != http.StatusBadRequest || out["code"] != "OTP_FAILED" {
		t.Fatalf("shopee error: %d %v", code, out)
	}

	// developer: boleh kelola aplikasi, tidak boleh menghubungkan merchant; viewer: hanya baca
	ctx := context.Background()
	for user, role := range map[string]string{"u-dev": ledger.RoleDeveloper, "u-viewer": ledger.RoleViewer} {
		_ = e.st.AddMember(ctx, ledger.Membership{OrgID: founderOrg, UserID: user, Email: user + "@uji.id", Role: role})
	}
	auth := e.srv.ConsoleAuth
	e.srv.ConsoleAuth = func(ctx context.Context, token string) (ConsoleUser, error) {
		switch token {
		case "tok-dev":
			return ConsoleUser{ID: "u-dev", Email: "u-dev@uji.id"}, nil
		case "tok-viewer":
			return ConsoleUser{ID: "u-viewer", Email: "u-viewer@uji.id"}, nil
		}
		return auth(ctx, token)
	}
	if code, _, _ := e.consoleCall("POST", "tok-dev", "merchants/otp/request", map[string]any{"phone": "0812", "password": "x"}); code != http.StatusForbidden {
		t.Fatalf("developer must not connect merchants: %d", code)
	}
	if code, _, _ := e.consoleCall("POST", "tok-dev", "apps", map[string]any{"name": "Proyek Dev", "merchant_id": "mch_777_88"}); code != http.StatusCreated {
		t.Fatalf("developer can create apps: %d", code)
	}
	if code, _, _ := e.consoleCall("POST", "tok-viewer", "apps", map[string]any{"name": "X", "merchant_id": "mch_777_88"}); code != http.StatusForbidden {
		t.Fatalf("viewer must be read-only: %d", code)
	}
	if code, _ := e.console("tok-viewer", "apps"); code != http.StatusOK {
		t.Fatalf("viewer can read: %d", code)
	}
}

func TestConsoleAppLifecycle(t *testing.T) {
	e := newEnv(t)
	e.manageEnv()

	// satu merchant, beberapa aplikasi/proyek
	_, a, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Booking Lapangan", "merchant_id": "mch_777_88"})
	_, b, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Toko Online", "merchant_id": "mch_777_88"})
	keyA, keyB := a["api_key"].(string), b["api_key"].(string)
	appA := a["app"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(keyA, "pgk_") || !strings.HasPrefix(a["client_key"].(string), clientKeyPrefix) || keyA == keyB {
		t.Fatalf("create app: %v", a)
	}
	e.invoice(keyA, "o-a", 10000)
	e.invoice(keyB, "o-b", 20000)
	_, apps := e.console("tok-founder", "apps")
	if len(apps["apps"].([]any)) != 2 {
		t.Fatalf("two apps on one merchant: %v", apps)
	}

	// merchant org lain tidak bisa dipakai, aplikasi org lain tidak bisa disentuh
	ctx := context.Background()
	_ = e.st.SaveMerchant(ctx, ledger.Merchant{ID: "mch_lain", Name: "Toko Lain", StaticQris: staticQris(t), Status: ledger.MerchantConnected, OrgID: "org_lain"})
	if code, _, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Curang", "merchant_id": "mch_lain"}); code != http.StatusNotFound {
		t.Fatalf("app on foreign merchant: %d", code)
	}
	if code, _, _ := e.consoleCall("DELETE", "tok-other", "apps/"+appA, nil); code != http.StatusNotFound {
		t.Fatalf("foreign app delete: %d", code)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "", "merchant_id": "mch_777_88"}); code != http.StatusBadRequest {
		t.Fatalf("empty name: %d", code)
	}

	// ganti nama
	if code, out, _ := e.consoleCall("PATCH", "tok-founder", "apps/"+appA, map[string]any{"name": "Booking Lapangan Pro"}); code != http.StatusOK || out["name"] != "Booking Lapangan Pro" {
		t.Fatalf("rename: %d %v", code, out)
	}
	// ganti secret key: key lama mati, key baru jalan
	_, roll, _ := e.consoleCall("POST", "tok-founder", "apps/"+appA+"/secret-key", nil)
	newKey := roll["api_key"].(string)
	if code, _ := e.do("GET", "/api/v2/merchant", keyA, nil); code != http.StatusUnauthorized {
		t.Fatalf("old secret key must stop working: %d", code)
	}
	if code, _ := e.do("GET", "/api/v2/merchant", newKey, nil); code != http.StatusOK {
		t.Fatalf("new secret key must work: %d", code)
	}
	// ganti client key & webhook
	if code, out, _ := e.consoleCall("POST", "tok-founder", "apps/"+appA+"/client-key", nil); code != http.StatusOK || out["client_key"] == a["client_key"] {
		t.Fatalf("roll client key: %d %v", code, out)
	}
	rc := newReceiver(t)
	e.srv.Webhooks = rc.srv.Client()
	if code, out, _ := e.consoleCall("PUT", "tok-founder", "apps/"+appA+"/webhook", map[string]any{"url": rc.srv.URL}); code != http.StatusOK || !strings.HasPrefix(out["webhook_secret"].(string), webhookSecretPrefix) {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if code, out, _ := e.consoleCall("POST", "tok-founder", "apps/"+appA+"/webhook/test", nil); code != http.StatusOK || out["success"] != true {
		t.Fatalf("webhook test: %d %v", code, out)
	}

	// hapus: key mati, aplikasi hilang dari daftar, aplikasi lain tetap jalan
	if code, _, _ := e.consoleCall("DELETE", "tok-founder", "apps/"+appA, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.do("GET", "/api/v2/merchant", newKey, nil); code != http.StatusUnauthorized {
		t.Fatalf("deleted app key must stop working: %d", code)
	}
	if code, _, _ := e.consoleCall("DELETE", "tok-founder", "apps/"+appA, nil); code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", code)
	}
	_, apps = e.console("tok-founder", "apps")
	if l := apps["apps"].([]any); len(l) != 1 || l[0].(map[string]any)["name"] != "Toko Online" {
		t.Fatalf("remaining apps: %v", apps)
	}
	if code, _ := e.do("GET", "/api/v2/merchant", keyB, nil); code != http.StatusOK {
		t.Fatalf("other app keeps working: %d", code)
	}
	// riwayat tagihan aplikasi yang dihapus tetap ada
	if _, inv := e.console("tok-founder", "invoices"); len(inv["invoices"].([]any)) != 2 {
		t.Fatalf("invoices of deleted app stay: %v", inv)
	}
}
