package v2api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doH seperti env.do, tetapi dengan header bebas (mis. X-Client-Key dari browser).
func (e *env) doH(method, path string, headers map[string]string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

type testApp struct{ secret, client, id string }

func (e *env) newAppKeys(name string) testApp {
	e.t.Helper()
	code, out := e.do("POST", "/api/v2/admin/apps", "admin-secret", map[string]any{"name": name, "merchant_id": "mch_777_88"})
	if code != http.StatusCreated {
		e.t.Fatalf("create app: %d %v", code, out)
	}
	client, _ := out["client_key"].(string)
	if !strings.HasPrefix(client, clientKeyPrefix) {
		e.t.Fatalf("create app must return a client key: %v", out)
	}
	return testApp{secret: out["api_key"].(string), client: client, id: out["app"].(map[string]any)["id"].(string)}
}

func (e *env) checkout(token, clientKey string) (int, map[string]any) {
	e.t.Helper()
	return e.doH("GET", "/api/v2/checkout/"+token, map[string]string{"X-Client-Key": clientKey}, nil)
}

func TestCheckoutTokenFlow(t *testing.T) {
	e := newEnv(t)
	app := e.newAppKeys("Booking Lapangan")
	inv := e.invoice(app.secret, "order-1", 25000)
	token, _ := inv["token"].(string)
	if !strings.HasPrefix(token, tokenPrefix) {
		t.Fatalf("create invoice must return a token: %v", inv)
	}
	if _, ok := inv["redirect_url"]; ok {
		t.Fatalf("redirect_url must be omitted without CHECKOUT_BASE_URL: %v", inv)
	}
	// field lama tetap ada untuk integrasi yang sudah berjalan
	if inv["id"] == nil || inv["qris_string"] == "" || inv["qris_image_base64"] == nil {
		t.Fatalf("existing fields must stay: %v", inv)
	}

	code, view := e.checkout(token, app.client)
	if code != http.StatusOK || view["status"] != "pending" || view["qris_string"] == "" || view["amount"] != float64(25000) {
		t.Fatalf("checkout view: %d %v", code, view)
	}
	if view["merchant"].(map[string]any)["name"] != "Kopi Senja" || view["theme"] != nil {
		t.Fatalf("merchant/theme: %v", view)
	}
	raw, _ := json.Marshal(view)
	for _, leak := range []string{"app_id", "transaction_id", inv["id"].(string), app.secret, "session"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("public checkout leaks %q: %s", leak, raw)
		}
	}

	e.shop.add(paidTx("TX1", 25000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(30 * time.Second)
	code, view = e.checkout(token, app.client)
	if code != http.StatusOK || view["status"] != "paid" || view["paid_at"] == nil {
		t.Fatalf("checkout must settle like the server API: %d %v", code, view)
	}
	if _, ok := view["qris_string"]; ok {
		t.Fatalf("paid invoice must not expose a QR any more: %v", view)
	}
	// server melihat hasil yang sama lewat secret key
	if got := e.status(app.secret, inv["id"].(string)); got["status"] != "paid" || got["transaction_id"] != "TX1" {
		t.Fatalf("server status: %v", got)
	}
}

func TestCheckoutRedirectURL(t *testing.T) {
	e := newEnv(t)
	e.srv.CheckoutBaseURL = "https://pay.example.id"
	app := e.newAppKeys("POS")
	inv := e.invoice(app.secret, "o", 10000)
	want := "https://pay.example.id/i/" + inv["token"].(string) + "?ck=" + app.client
	if inv["redirect_url"] != want {
		t.Fatalf("redirect_url: got %v want %s", inv["redirect_url"], want)
	}
	// halaman bayar membuka tagihan dengan token + ck dari redirect_url
	if code, _ := e.checkout(inv["token"].(string), app.client); code != http.StatusOK {
		t.Fatalf("redirect_url pair must open checkout: %d", code)
	}

	// aplikasi lama tanpa client key: otomatis dibuatkan saat membuat tagihan
	if err := e.st.SetClientKey(context.Background(), app.id, ""); err != nil {
		t.Fatal(err)
	}
	old := e.invoice(app.secret, "o2", 10000)
	stored, _ := e.st.AppByID(context.Background(), app.id)
	if !strings.HasPrefix(stored.ClientKey, clientKeyPrefix) {
		t.Fatalf("legacy app must get a client key: %+v", stored)
	}
	if old["redirect_url"] != "https://pay.example.id/i/"+old["token"].(string)+"?ck="+stored.ClientKey || old["warning"] != nil {
		t.Fatalf("legacy app redirect_url: %v", old)
	}
	if code, _ := e.checkout(old["token"].(string), stored.ClientKey); code != http.StatusOK {
		t.Fatalf("auto client key must open checkout: %d", code)
	}
	// secret key lama tetap berlaku
	if got := e.status(app.secret, old["id"].(string)); got["status"] != "pending" {
		t.Fatalf("secret key must keep working: %v", got)
	}
}

func TestCheckoutRejectsWrongKeysAndTokens(t *testing.T) {
	e := newEnv(t)
	a := e.newAppKeys("A")
	b := e.newAppKeys("B")
	token := e.invoice(a.secret, "o", 10000)["token"].(string)

	if code, _ := e.checkout(token, ""); code != http.StatusUnauthorized {
		t.Fatalf("missing client key: %d", code)
	}
	for name, ck := range map[string]string{"wrong": "pgk_pub_palsu", "other app": b.client, "secret key": a.secret} {
		if code, _ := e.checkout(token, ck); code != http.StatusNotFound {
			t.Fatalf("%s client key must 404, got %d", name, code)
		}
	}
	if code, _ := e.checkout("ctk_tidakada", a.client); code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", code)
	}
	// secret key di Authorization tidak membuka checkout tanpa client key yang benar
	if code, _ := e.doH("GET", "/api/v2/checkout/"+token, map[string]string{"Authorization": "Bearer " + a.secret}, nil); code != http.StatusUnauthorized {
		t.Fatalf("secret key alone must not open checkout: %d", code)
	}
	if code, _ := e.doH("POST", "/api/v2/checkout/"+token, map[string]string{"X-Client-Key": a.client}, nil); code != http.StatusNotFound {
		t.Fatalf("only GET is allowed: %d", code)
	}
	// masih bisa dilihat sebentar setelah kedaluwarsa, lalu hilang
	e.clock = e.clock.Add(15 * time.Minute)
	if code, view := e.checkout(token, a.client); code != http.StatusOK || view["status"] != "expired" {
		t.Fatalf("expired invoice view: %d %v", code, view)
	}
	e.clock = e.clock.Add(checkoutViewGrace)
	if code, _ := e.checkout(token, a.client); code != http.StatusNotFound {
		t.Fatalf("token must stop working after the grace period: %d", code)
	}
}

func TestCheckoutPollingIsThrottled(t *testing.T) {
	e := newEnv(t)
	app := e.newAppKeys("POS")
	token := e.invoice(app.secret, "o", 10000)["token"].(string)

	e.checkout(token, app.client)
	e.clock = e.clock.Add(time.Second)
	e.checkout(token, app.client)
	e.checkout(token, app.client)
	if e.shop.recentCalls != 1 {
		t.Fatalf("polls within %s must hit Shopee once, got %d", checkoutPollGap, e.shop.recentCalls)
	}
	e.clock = e.clock.Add(checkoutPollGap)
	e.checkout(token, app.client)
	if e.shop.recentCalls != 2 {
		t.Fatalf("poll after the gap must check Shopee again, got %d", e.shop.recentCalls)
	}
}

func TestCheckoutNewTokenPerCreate(t *testing.T) {
	e := newEnv(t)
	app := e.newAppKeys("POS")
	first := e.invoice(app.secret, "o", 10000)
	code, again := e.do("POST", "/api/v2/invoices", app.secret, map[string]any{"order_id": "o", "amount": 10000})
	if code != http.StatusOK || again["id"] != first["id"] || again["token"] == first["token"] || again["token"] == nil {
		t.Fatalf("idempotent create must reuse the invoice with a fresh token: %d %v", code, again)
	}
	for _, tok := range []any{first["token"], again["token"]} {
		if code, _ := e.checkout(tok.(string), app.client); code != http.StatusOK {
			t.Fatalf("both tokens must open the invoice: %d", code)
		}
	}
}

func TestClientKeyRoll(t *testing.T) {
	e := newEnv(t)
	app := e.newAppKeys("POS")
	token := e.invoice(app.secret, "o", 10000)["token"].(string)

	code, out := e.do("POST", "/api/v2/admin/apps/"+app.id+"/client-key", "admin-secret", nil)
	newKey, _ := out["client_key"].(string)
	if code != http.StatusOK || !strings.HasPrefix(newKey, clientKeyPrefix) || newKey == app.client {
		t.Fatalf("roll client key: %d %v", code, out)
	}
	if code, _ := e.checkout(token, app.client); code != http.StatusNotFound {
		t.Fatalf("old client key must stop working: %d", code)
	}
	if code, _ := e.checkout(token, newKey); code != http.StatusOK {
		t.Fatalf("new client key must work: %d", code)
	}
	if code, _ := e.do("POST", "/api/v2/admin/apps/app_tidakada/client-key", "admin-secret", nil); code != http.StatusNotFound {
		t.Fatalf("unknown app: %d", code)
	}
	if code, _ := e.do("POST", "/api/v2/admin/apps/"+app.id+"/client-key", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("roll requires admin: %d", code)
	}
	// client key bisa dilihat lagi kapan saja lewat daftar aplikasi
	_, list := e.do("GET", "/api/v2/admin/apps", "admin-secret", nil)
	apps := list["apps"].([]any)
	if apps[0].(map[string]any)["client_key"] != newKey {
		t.Fatalf("app list must show the client key: %v", list)
	}
}

func TestCheckoutTheme(t *testing.T) {
	e := newEnv(t)
	valid := map[string]any{
		"display_name": "Kopi Senja Dago", "logo_text": "KS", "logo_url": "", "brand_color": "#EA580C",
		"appearance": "dark", "corner": "pill", "layout": "popup", "headline": "Scan QRIS untuk membayar",
		"show_timer": true, "show_wallets": true, "show_order_id": false, "show_cancel": true,
	}
	path := "/api/v2/admin/merchants/mch_777_88/checkout-theme"
	for field, bad := range map[string]any{
		"brand_color": "orange", "appearance": "neon", "corner": "round", "layout": "modal",
		"logo_url": "javascript:alert(1)", "display_name": strings.Repeat("x", 41),
	} {
		body := map[string]any{}
		for k, v := range valid {
			body[k] = v
		}
		body[field] = bad
		if code, _ := e.do("PUT", path, "admin-secret", body); code != http.StatusBadRequest {
			t.Fatalf("invalid %s must be rejected, got %d", field, code)
		}
	}
	if code, _ := e.do("PUT", "/api/v2/admin/merchants/mch_tidakada/checkout-theme", "admin-secret", valid); code != http.StatusNotFound {
		t.Fatalf("unknown merchant: %d", code)
	}
	if code, _ := e.do("PUT", path, "", valid); code != http.StatusUnauthorized {
		t.Fatalf("theme requires admin: %d", code)
	}
	if code, out := e.do("PUT", path, "admin-secret", valid); code != http.StatusOK {
		t.Fatalf("save theme: %d %v", code, out)
	}
	if _, out := e.do("GET", path, "admin-secret", nil); out["theme"].(map[string]any)["brand_color"] != "#EA580C" {
		t.Fatalf("get theme: %v", out)
	}

	app := e.newAppKeys("POS")
	token := e.invoice(app.secret, "o", 10000)["token"].(string)
	_, view := e.checkout(token, app.client)
	theme, _ := view["theme"].(map[string]any)
	if theme["appearance"] != "dark" || theme["display_name"] != "Kopi Senja Dago" {
		t.Fatalf("checkout must carry the merchant theme: %v", view)
	}
}
