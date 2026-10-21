package v2api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/shopee"
)

// testEnv: merchant terputus tanpa QRIS (mode test tetap jalan), Shopee dilarang dipanggil.
func (e *env) testModeEnv() (live, test, testAppID string, rc *receiver) {
	e.manageEnv()
	e.srv.NewClient = func(*shopee.Session) ShopeeClient {
		e.t.Fatal("mode test tidak boleh memanggil Shopee")
		return nil
	}
	ctx := context.Background()
	m, _ := e.st.GetMerchant(ctx, "mch_777_88")
	m.Status, m.StaticQris, m.SessionJSON = ledger.MerchantDisconnected, "", nil
	_ = e.st.SaveMerchant(ctx, m)

	_, l, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Live", "merchant_id": "mch_777_88"})
	code, t, raw := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Sandbox", "merchant_id": "mch_777_88", "mode": "test"})
	if code != http.StatusCreated {
		e.t.Fatalf("create test app: %d %s", code, raw)
	}
	testAppID = t["app"].(map[string]any)["id"].(string)
	rc = newReceiver(e.t)
	e.srv.Webhooks = rc.srv.Client()
	e.consoleCall("PUT", "tok-founder", "apps/"+testAppID+"/webhook", map[string]any{"url": rc.srv.URL})
	return l["api_key"].(string), t["api_key"].(string), testAppID, rc
}

func TestTestModeKeysAndInvoice(t *testing.T) {
	e := newEnv(t)
	live, test, appID, rc := e.testModeEnv()

	if !strings.HasPrefix(test, testSecretPrefix) || strings.HasPrefix(live, testSecretPrefix) {
		t.Fatalf("key prefixes: live=%q test=%q", live[:9], test[:9])
	}
	_, apps := e.console("tok-founder", "apps")
	for _, raw := range apps["apps"].([]any) {
		a := raw.(map[string]any)
		if a["id"] == appID && (a["mode"] != "test" || !strings.HasPrefix(a["client_key"].(string), testClientPrefix)) {
			t.Fatalf("test app view: %v", a)
		}
	}

	// live butuh merchant terhubung; test tidak
	if code, out := e.do("POST", "/api/v2/invoices", live, map[string]any{"order_id": "L1", "amount": 5000}); code != http.StatusServiceUnavailable {
		t.Fatalf("live invoice on disconnected merchant: %d %v", code, out)
	}
	inv := e.invoice(test, "T1", 25000)
	if inv["mode"] != "test" || !strings.HasPrefix(inv["qris_string"].(string), "CRAVEPAY-TEST|") || inv["qris_image_base64"] == nil {
		t.Fatalf("test invoice: %v", inv)
	}
	id := inv["id"].(string)
	if st := e.status(test, id); st["status"] != "pending" {
		t.Fatalf("status without Shopee: %v", st)
	}

	// key live tidak bisa simulasi; key test bisa
	if code, _ := e.do("POST", "/api/v2/invoices/"+id+"/simulate", live, nil); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatalf("live key simulate: %d", code)
	}
	code, paid := e.do("POST", "/api/v2/invoices/"+id+"/simulate", test, map[string]any{"status": "paid"})
	if code != http.StatusOK || paid["status"] != "paid" || paid["payment_type"] != simulatedPaymentType || !strings.HasPrefix(paid["transaction_id"].(string), "TEST") {
		t.Fatalf("simulate paid: %d %v", code, paid)
	}
	if code, out := e.do("POST", "/api/v2/invoices/"+id+"/simulate", test, nil); code != http.StatusConflict || out["code"] != "NOT_PENDING" {
		t.Fatalf("simulate twice: %d %v", code, out)
	}
	// webhook invoice.paid terkirim dengan mode test
	calls := rc.calls()
	if len(calls) != 1 || calls[0].event != "invoice.paid" {
		t.Fatalf("webhook calls: %+v", calls)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(calls[0].body, &body)
	if body.Data["mode"] != "test" || body.Data["order_id"] != "T1" {
		t.Fatalf("webhook body: %s", calls[0].body)
	}

	// kedaluwarsa: lewat waktu → expired + webhook
	inv2 := e.invoice(test, "T2", 1000)
	e.clock = e.clock.Add(11 * time.Minute)
	if st := e.status(test, inv2["id"].(string)); st["status"] != "expired" {
		t.Fatalf("test invoice must expire: %v", st)
	}
	if calls := rc.calls(); len(calls) != 2 || calls[1].event != "invoice.expired" {
		t.Fatalf("expired webhook: %+v", calls)
	}
}

func TestTestModeConsoleAndCheckout(t *testing.T) {
	e := newEnv(t)
	e.srv.CheckoutBaseURL = "https://pay.contoh.id"
	_, _, appID, rc := e.testModeEnv()
	_, apps := e.console("tok-founder", "apps")
	var liveID string
	for _, raw := range apps["apps"].([]any) {
		if a := raw.(map[string]any); a["mode"] == "live" {
			liveID = a["id"].(string)
		}
	}

	// tagihan uji hanya dari aplikasi test
	if code, out, _ := e.consoleCall("POST", "tok-founder", "apps/"+liveID+"/test-invoice", map[string]any{"amount": 5000}); code != http.StatusForbidden || out["code"] != "LIVE_MODE" {
		t.Fatalf("live test-invoice: %d %v", code, out)
	}
	code, inv, raw := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/test-invoice", map[string]any{"amount": 15000})
	if code != http.StatusCreated || !strings.HasPrefix(inv["order_id"].(string), "UJI-") || inv["redirect_url"] == nil {
		t.Fatalf("console test invoice: %d %s", code, raw)
	}
	id := inv["id"].(string)

	// halaman checkout publik menandai mode test
	app, _ := e.st.AppByID(context.Background(), appID)
	code, page := e.doH("GET", "/api/v2/checkout/"+inv["token"].(string), map[string]string{"X-Client-Key": app.ClientKey}, nil)
	if code != http.StatusOK || page["mode"] != "test" || page["status"] != "pending" {
		t.Fatalf("checkout: %d %v", code, page)
	}

	// viewer tidak bisa simulasi; org lain tidak bisa menyentuh
	if code, _, _ := e.consoleCall("POST", "tok-other", "apps/"+appID+"/invoices/"+id+"/simulate", nil); code != http.StatusNotFound {
		t.Fatalf("foreign simulate: %d", code)
	}
	code, out, _ := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/invoices/"+id+"/simulate", map[string]any{"status": "paid"})
	if code != http.StatusOK || out["status"] != "paid" {
		t.Fatalf("console simulate: %d %v", code, out)
	}
	if len(rc.calls()) != 1 {
		t.Fatalf("console simulate must send the webhook: %+v", rc.calls())
	}
	// daftar tagihan console membawa mode
	_, list := e.console("tok-founder", "invoices")
	if l := list["invoices"].([]any); len(l) != 1 || l[0].(map[string]any)["mode"] != "test" {
		t.Fatalf("console invoices: %v", list)
	}
}
