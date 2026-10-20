package v2api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

/* ---------------------------------------------------- penerima webhook palsu */

type received struct {
	event, eventID, signature string
	body                      []byte
}

type receiver struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	got    []received
	status []int // status balasan berurutan; setelah habis selalu 200
}

func newReceiver(t *testing.T, statuses ...int) *receiver {
	rc := &receiver{t: t, status: statuses}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.got = append(rc.got, received{
			event: r.Header.Get("X-CravePay-Event"), eventID: r.Header.Get("X-CravePay-Event-Id"),
			signature: r.Header.Get("X-CravePay-Signature"), body: body,
		})
		code := http.StatusOK
		if len(rc.status) > 0 {
			code, rc.status = rc.status[0], rc.status[1:]
		}
		rc.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *receiver) calls() []received {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]received(nil), rc.got...)
}

// verify memeriksa tanda tangan seperti yang harus dilakukan server toko.
func verify(t *testing.T, secret string, r received) {
	t.Helper()
	var ts int64
	var sig string
	for _, part := range strings.Split(r.signature, ",") {
		if v, ok := strings.CutPrefix(part, "t="); ok {
			fmt.Sscan(v, &ts)
		}
		if v, ok := strings.CutPrefix(part, "v1="); ok {
			sig = v
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", ts, r.body)
	if ts == 0 || !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatalf("signature does not verify: %q", r.signature)
	}
}

func (e *env) webhookEnv(rc *receiver) {
	e.srv.AllowInsecureWebhooks = true
	e.srv.Webhooks = rc.srv.Client()
	e.srv.CronSecret = "cron-secret"
}

func (e *env) setWebhook(appID, url string) string {
	e.t.Helper()
	code, out := e.do("PUT", "/api/v2/admin/apps/"+appID+"/webhook", "admin-secret", map[string]any{"url": url})
	if code != http.StatusOK {
		e.t.Fatalf("set webhook: %d %v", code, out)
	}
	return out["webhook_secret"].(string)
}

func (e *env) sweep() map[string]any {
	e.t.Helper()
	code, out := e.do("POST", "/api/v2/internal/sweep", "cron-secret", nil)
	if code != http.StatusOK {
		e.t.Fatalf("sweep: %d %v", code, out)
	}
	return out["summary"].(map[string]any)
}

func eventData(t *testing.T, r received) map[string]any {
	t.Helper()
	var ev struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(r.body, &ev); err != nil {
		t.Fatal(err)
	}
	return ev.Data
}

/* ---------------------------------------------------------------- tes */

func TestWebhookPaidIsSignedAndSentOnce(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	secret := e.setWebhook(app.id, rc.srv.URL+"/hooks/crave")
	if !strings.HasPrefix(secret, webhookSecretPrefix) {
		t.Fatalf("secret: %q", secret)
	}

	inv := e.invoice(app.secret, "order-1", 25000)
	e.shop.add(paidTx("TX1", 25000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(20 * time.Second)
	e.status(app.secret, inv["id"].(string))
	e.status(app.secret, inv["id"].(string)) // dicek lagi: tidak boleh kirim dua kali

	got := rc.calls()
	if len(got) != 1 || got[0].event != "invoice.paid" || !strings.HasPrefix(got[0].eventID, "evt_") {
		t.Fatalf("want one invoice.paid, got %+v", got)
	}
	verify(t, secret, got[0])
	data := eventData(t, got[0])
	if data["order_id"] != "order-1" || data["transaction_id"] != "TX1" || data["status"] != "paid" {
		t.Fatalf("payload: %v", data)
	}
	_, list := e.do("GET", "/api/v2/admin/apps/"+app.id+"/webhook/events", "admin-secret", nil)
	evs := list["events"].([]any)
	if len(evs) != 1 || evs[0].(map[string]any)["status"] != "delivered" {
		t.Fatalf("event log: %v", list)
	}
}

func TestWebhookPaidViaPublicCheckout(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	e.setWebhook(app.id, rc.srv.URL)
	token := e.invoice(app.secret, "o", 10000)["token"].(string)
	e.shop.add(paidTx("TX", 10000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(10 * time.Second)
	if _, view := e.checkout(token, app.client); view["status"] != "paid" {
		t.Fatalf("checkout: %v", view)
	}
	if got := rc.calls(); len(got) != 1 || got[0].event != "invoice.paid" {
		t.Fatalf("popup polling must trigger the webhook: %+v", got)
	}
}

func TestWebhookRetriedBySweep(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t, http.StatusInternalServerError, http.StatusBadGateway)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	secret := e.setWebhook(app.id, rc.srv.URL)
	inv := e.invoice(app.secret, "o", 10000)
	e.shop.add(paidTx("TX", 10000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(10 * time.Second)
	e.status(app.secret, inv["id"].(string)) // percobaan 1: 500

	if sum := e.sweep(); sum["delivered"] != float64(0) || len(rc.calls()) != 1 {
		t.Fatalf("retry must wait for its backoff: %v calls=%d", sum, len(rc.calls()))
	}
	e.clock = e.clock.Add(retryBackoff[0])
	e.sweep() // percobaan 2: 502
	e.clock = e.clock.Add(retryBackoff[1])
	if sum := e.sweep(); sum["delivered"] != float64(1) { // percobaan 3: 200
		t.Fatalf("third attempt should deliver: %v", sum)
	}
	got := rc.calls()
	if len(got) != 3 || got[0].eventID != got[2].eventID {
		t.Fatalf("retries must reuse the event id: %+v", got)
	}
	verify(t, secret, got[2])
	e.clock = e.clock.Add(time.Hour)
	e.sweep()
	if len(rc.calls()) != 3 {
		t.Fatal("delivered event must not be sent again")
	}
}

func TestWebhookGivesUpAfterRetries(t *testing.T) {
	e := newEnv(t)
	statuses := make([]int, 20)
	for i := range statuses {
		statuses[i] = http.StatusServiceUnavailable
	}
	rc := newReceiver(t, statuses...)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	e.setWebhook(app.id, rc.srv.URL)
	inv := e.invoice(app.secret, "o", 10000)
	e.shop.add(paidTx("TX", 10000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(10 * time.Second)
	e.status(app.secret, inv["id"].(string))
	for _, d := range retryBackoff {
		e.clock = e.clock.Add(d)
		e.sweep()
	}
	if n := len(rc.calls()); n != 1+len(retryBackoff) {
		t.Fatalf("want %d attempts, got %d", 1+len(retryBackoff), n)
	}
	_, list := e.do("GET", "/api/v2/admin/apps/"+app.id+"/webhook/events", "admin-secret", nil)
	ev := list["events"].([]any)[0].(map[string]any)
	if ev["status"] != "failed" || ev["last_error"] != "HTTP 503" {
		t.Fatalf("event must end failed: %v", ev)
	}
	e.clock = e.clock.Add(48 * time.Hour)
	e.sweep()
	if len(rc.calls()) != 1+len(retryBackoff) {
		t.Fatal("failed event must stay failed")
	}
}

func TestSweepSettlesUnwatchedInvoices(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	e.setWebhook(app.id, rc.srv.URL)
	a := e.invoice(app.secret, "a", 10000)["id"].(string)
	b := e.invoice(app.secret, "b", 20000)["id"].(string)
	// tidak ada yang mengecek; pelanggan membayar keduanya
	e.shop.add(paidTx("TA", 10000, e.clock.Add(5*time.Second)))
	e.shop.add(paidTx("TB", 20000, e.clock.Add(6*time.Second)))
	e.clock = e.clock.Add(30 * time.Second)

	sum := e.sweep()
	if sum["paid"] != float64(2) || e.shop.recentCalls != 1 {
		t.Fatalf("sweep must settle both with one Shopee read: %v recent=%d", sum, e.shop.recentCalls)
	}
	if len(rc.calls()) != 2 {
		t.Fatalf("both invoices must be announced: %+v", rc.calls())
	}
	if e.status(app.secret, a)["status"] != "paid" || e.status(app.secret, b)["status"] != "paid" {
		t.Fatal("invoices must be stored as paid")
	}
	// sweep berikutnya tidak menyentuh tagihan yang sudah lunas
	e.clock = e.clock.Add(time.Minute)
	if sum := e.sweep(); sum["checked"] != float64(0) {
		t.Fatalf("paid invoices must not be swept again: %v", sum)
	}
}

func TestSweepSkipsRecentlyCheckedAndExpires(t *testing.T) {
	e := newEnv(t)
	rc := newReceiver(t)
	e.webhookEnv(rc)
	app := e.newAppKeys("POS")
	e.setWebhook(app.id, rc.srv.URL)
	token := e.invoice(app.secret, "o", 10000)["token"].(string)

	e.checkout(token, app.client) // popup baru saja mengecek
	if sum := e.sweep(); sum["checked"] != float64(0) {
		t.Fatalf("invoice checked moments ago must be skipped: %v", sum)
	}
	e.clock = e.clock.Add(13 * time.Minute)
	if sum := e.sweep(); sum["expired"] != float64(1) {
		t.Fatalf("overdue invoice must expire: %v", sum)
	}
	if got := rc.calls(); len(got) != 1 || got[0].event != "invoice.expired" {
		t.Fatalf("want invoice.expired: %+v", got)
	}
}

func TestSweepRequiresCronSecret(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "salah", "admin-secret"} {
		if code, _ := e.do("POST", "/api/v2/internal/sweep", tok, nil); code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", tok, code)
		}
	}
	e.srv.CronSecret = "cron-secret"
	if code, _ := e.do("GET", "/api/v2/internal/sweep", "cron-secret", nil); code != http.StatusNotFound {
		t.Fatalf("only POST: %d", code)
	}
}

func TestWebhookAdmin(t *testing.T) {
	e := newEnv(t)
	app := e.newAppKeys("POS")
	for _, bad := range []string{"http://toko.id/h", "https://localhost/h", "https://127.0.0.1/h", "https://10.1.2.3/h",
		"https://192.168.1.5/h", "https://169.254.169.254/latest", "https://u:p@toko.id/h", "javascript:alert(1)", "ftp://toko.id"} {
		if code, _ := e.do("PUT", "/api/v2/admin/apps/"+app.id+"/webhook", "admin-secret", map[string]any{"url": bad}); code != http.StatusBadRequest {
			t.Fatalf("%s must be rejected, got %d", bad, code)
		}
	}
	if code, _ := e.do("PUT", "/api/v2/admin/apps/"+app.id+"/webhook", "", map[string]any{"url": "https://toko.id/h"}); code != http.StatusUnauthorized {
		t.Fatalf("requires admin: %d", code)
	}
	if code, _ := e.do("PUT", "/api/v2/admin/apps/app_x/webhook", "admin-secret", map[string]any{"url": "https://toko.id/h"}); code != http.StatusNotFound {
		t.Fatalf("unknown app: %d", code)
	}

	rc := newReceiver(t)
	e.webhookEnv(rc)
	first := e.setWebhook(app.id, rc.srv.URL)
	if again := e.setWebhook(app.id, rc.srv.URL+"/baru"); again != first {
		t.Fatal("changing the URL must keep the secret")
	}
	_, rot := e.do("POST", "/api/v2/admin/apps/"+app.id+"/webhook/secret", "admin-secret", nil)
	rotated := rot["webhook_secret"].(string)
	if rotated == first {
		t.Fatal("rotate must change the secret")
	}
	code, ping := e.do("POST", "/api/v2/admin/apps/"+app.id+"/webhook/test", "admin-secret", nil)
	got := rc.calls()
	if code != http.StatusOK || ping["success"] != true || len(got) != 1 || got[0].event != "ping" {
		t.Fatalf("ping: %d %v %+v", code, ping, got)
	}
	verify(t, rotated, got[0])

	// url kosong mematikan webhook: tagihan lunas tidak mengirim apa-apa
	e.setWebhook(app.id, "")
	inv := e.invoice(app.secret, "o", 10000)
	e.shop.add(paidTx("TX", 10000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(10 * time.Second)
	e.status(app.secret, inv["id"].(string))
	if len(rc.calls()) != 1 {
		t.Fatal("disabled webhook must not send")
	}
	if code, out := e.do("POST", "/api/v2/admin/apps/"+app.id+"/webhook/test", "admin-secret", nil); code != http.StatusBadRequest {
		t.Fatalf("test without url: %d %v", code, out)
	}
}
