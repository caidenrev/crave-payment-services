package v2api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hirotomasato/paygateme/core"
	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/qris"
	"github.com/hirotomasato/paygateme/shopee"
)

/* ---------------------------------------------------------- fake Shopee */

type fakeShopee struct {
	mu          sync.Mutex
	txs         []core.MerchantTransaction
	recentErr   error // dikembalikan sekali oleh Recent
	refreshErr  error
	refreshes   int
	renewCookie string
}

type fakeClient struct {
	f    *fakeShopee
	sess shopee.Session
}

func (c *fakeClient) Recent(_ context.Context, _, _ time.Time) ([]core.MerchantTransaction, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	if c.f.recentErr != nil {
		err := c.f.recentErr
		c.f.recentErr = nil
		return nil, err
	}
	return append([]core.MerchantTransaction(nil), c.f.txs...), nil
}

func (c *fakeClient) Refresh(context.Context) error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.refreshes++
	if c.f.refreshErr != nil {
		return c.f.refreshErr
	}
	if c.f.renewCookie != "" {
		c.sess.Cookies = []shopee.Cookie{{Name: "SPC_EC", Value: c.f.renewCookie}}
	}
	return nil
}

func (c *fakeClient) Session() *shopee.Session { s := c.sess; return &s }

func (f *fakeShopee) add(tx core.MerchantTransaction) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txs = append(f.txs, tx)
}

/* --------------------------------------------------------------- setup */

type env struct {
	t     *testing.T
	srv   *Server
	st    *ledger.MemoryStore
	shop  *fakeShopee
	clock time.Time
}

func staticQris(t *testing.T) string {
	t.Helper()
	p, err := qris.BuildEmv(qris.EmvTlvMap{
		qris.TagPayloadFormat: "01", qris.TagPointOfInitiation: qris.POIStatic,
		"26": "0012BR.COM.GOPAY00111111111111111111", "52": "5912", "53": "360",
		"58": "ID", "59": "MERCHANT", "60": "Bandung", "61": "40123",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, st: ledger.NewMemoryStore(), shop: &fakeShopee{}, clock: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)}
	sess, _ := json.Marshal(shopee.Session{Merchant: shopee.MerchantSummary{ID: "777", Name: "Kopi Senja"}, StoreID: "88"})
	_ = e.st.SaveMerchant(context.Background(), ledger.Merchant{
		ID: "mch_777_88", Name: "Kopi Senja", ShopeeMerchantID: "777", StoreID: "88",
		StaticQris: staticQris(t), SessionJSON: sess, Status: ledger.MerchantConnected,
	})
	e.srv = &Server{
		Store: e.st, AdminToken: "admin-secret",
		NewClient: func(s *shopee.Session) ShopeeClient { return &fakeClient{f: e.shop, sess: *s} },
		Now:       func() time.Time { return e.clock },
	}
	return e
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *env) newApp(name string) string {
	e.t.Helper()
	code, out := e.do("POST", "/api/v2/admin/apps", "admin-secret", map[string]any{"name": name, "merchant_id": "mch_777_88"})
	if code != http.StatusCreated {
		e.t.Fatalf("create app: %d %v", code, out)
	}
	return out["api_key"].(string)
}

func (e *env) invoice(key, order string, amount int64) map[string]any {
	e.t.Helper()
	code, out := e.do("POST", "/api/v2/invoices", key, map[string]any{"order_id": order, "amount": amount})
	if code != http.StatusCreated {
		e.t.Fatalf("create invoice: %d %v", code, out)
	}
	return out
}

func (e *env) status(key, id string) map[string]any {
	e.t.Helper()
	_, out := e.do("GET", "/api/v2/invoices/"+id, key, nil)
	return out
}

func paidTx(id string, amount int64, at time.Time) core.MerchantTransaction {
	return core.MerchantTransaction{ID: id, Amount: amount, Status: "completed", Time: at, PaymentType: "shopee:1"}
}

/* --------------------------------------------------------------- tests */

func TestAdminRequiresToken(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do("GET", "/api/v2/admin/merchants", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.do("GET", "/api/v2/admin/merchants", "salah", nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	e.srv.AdminToken = ""
	if code, _ := e.do("GET", "/api/v2/admin/merchants", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("admin must be disabled without ADMIN_TOKEN: %d", code)
	}
}

func TestAdminListNeverLeaksSession(t *testing.T) {
	e := newEnv(t)
	_, out := e.do("GET", "/api/v2/admin/merchants", "admin-secret", nil)
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte("777\",\"Name")) || bytes.Contains(raw, []byte("cookies")) || bytes.Contains(raw, []byte("session")) {
		t.Fatalf("merchant list leaks session: %s", raw)
	}
	if bytes.Contains(raw, []byte("0012BR.COM.GOPAY")) {
		t.Fatalf("merchant list leaks static QRIS: %s", raw)
	}
}

func TestAppKeyRequired(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.do("POST", "/api/v2/invoices", "", map[string]any{"order_id": "o", "amount": 1000}); code != http.StatusUnauthorized {
		t.Fatalf("no key: %d", code)
	}
	if code, _ := e.do("POST", "/api/v2/invoices", "pgk_palsu", map[string]any{"order_id": "o", "amount": 1000}); code != http.StatusUnauthorized {
		t.Fatalf("bad key: %d", code)
	}
}

func TestInvoiceLifecycle(t *testing.T) {
	e := newEnv(t)
	key := e.newApp("Crave POS")
	inv := e.invoice(key, "order-1", 25000)
	if inv["status"] != "pending" || inv["qris_string"] == "" || inv["qris_image_base64"] == nil {
		t.Fatalf("bad invoice: %v", inv)
	}
	id := inv["id"].(string)

	e.clock = e.clock.Add(20 * time.Second)
	if got := e.status(key, id); got["status"] != "pending" {
		t.Fatalf("no payment yet: %v", got)
	}
	e.shop.add(paidTx("TX1", 25000, e.clock.Add(5*time.Second)))
	e.clock = e.clock.Add(30 * time.Second)
	got := e.status(key, id)
	if got["status"] != "paid" || got["transaction_id"] != "TX1" {
		t.Fatalf("want paid by TX1: %v", got)
	}
	// order_id sama → tagihan yang sama (idempoten), nominal beda → 409
	if code, again := e.do("POST", "/api/v2/invoices", key, map[string]any{"order_id": "order-1", "amount": 25000}); code != http.StatusOK || again["id"] != id {
		t.Fatalf("idempotent create: %d %v", code, again)
	}
	if code, _ := e.do("POST", "/api/v2/invoices", key, map[string]any{"order_id": "order-1", "amount": 30000}); code != http.StatusConflict {
		t.Fatalf("different amount must conflict: %d", code)
	}
}

func TestSameAmountAcrossAppsAndInvoices(t *testing.T) {
	e := newEnv(t)
	pos := e.newApp("Crave POS")
	saas := e.newApp("SaaS lain")
	a := e.invoice(pos, "a", 50000)["id"].(string)
	b := e.invoice(saas, "b", 50000)["id"].(string)

	e.shop.add(paidTx("ONE", 50000, e.clock.Add(time.Minute)))
	e.clock = e.clock.Add(70 * time.Second)
	sa, sb := e.status(pos, a), e.status(saas, b)
	if sa["status"] != "paid" || sb["status"] != "pending" {
		t.Fatalf("one payment must pay one invoice: a=%v b=%v", sa["status"], sb["status"])
	}
	// aplikasi lain tidak bisa membaca tagihan milik aplikasi lain
	if code, _ := e.do("GET", "/api/v2/invoices/"+a, saas, nil); code != http.StatusNotFound {
		t.Fatalf("cross-app read must 404, got %d", code)
	}
	e.shop.add(paidTx("TWO", 50000, e.clock.Add(10*time.Second)))
	e.clock = e.clock.Add(20 * time.Second)
	if sb = e.status(saas, b); sb["status"] != "paid" || sb["transaction_id"] != "TWO" {
		t.Fatalf("b should be paid by TWO: %v", sb)
	}
}

func TestSessionRenewedOnceAndSaved(t *testing.T) {
	e := newEnv(t)
	key := e.newApp("POS")
	id := e.invoice(key, "o", 10000)["id"].(string)
	e.shop.recentErr = errors.New("token expired")
	e.shop.renewCookie = "baru"
	e.shop.add(paidTx("T", 10000, e.clock.Add(10*time.Second)))
	e.clock = e.clock.Add(20 * time.Second)
	if got := e.status(key, id); got["status"] != "paid" {
		t.Fatalf("should pay after silent refresh: %v", got)
	}
	m, _ := e.st.GetMerchant(context.Background(), "mch_777_88")
	if !bytes.Contains(m.SessionJSON, []byte("baru")) || e.shop.refreshes != 1 {
		t.Fatalf("renewed session must be stored once: refreshes=%d session=%s", e.shop.refreshes, m.SessionJSON)
	}
}

func TestDisconnectedMerchant(t *testing.T) {
	e := newEnv(t)
	key := e.newApp("POS")
	id := e.invoice(key, "o", 10000)["id"].(string)
	e.shop.recentErr = errors.New("unauthorized")
	e.shop.refreshErr = core.NewAuthError(core.CodeAuthRequired, "expired", nil)
	got := e.status(key, id)
	if got["status"] != "pending" || got["warning"] != "MERCHANT_DISCONNECTED" {
		t.Fatalf("want pending + warning: %v", got)
	}
	if code, out := e.do("POST", "/api/v2/invoices", key, map[string]any{"order_id": "o2", "amount": 1000}); code != http.StatusServiceUnavailable || out["code"] != "MERCHANT_DISCONNECTED" {
		t.Fatalf("new invoices must be refused while disconnected: %d %v", code, out)
	}
	// tetap kedaluwarsa walau Shopee terputus
	e.clock = e.clock.Add(13 * time.Minute)
	if got := e.status(key, id); got["status"] != "expired" {
		t.Fatalf("want expired: %v", got)
	}
}

func TestInvoiceValidation(t *testing.T) {
	e := newEnv(t)
	key := e.newApp("POS")
	for _, body := range []map[string]any{
		{"order_id": "", "amount": 1000},
		{"order_id": "x", "amount": 0},
		{"order_id": "x", "amount": 200000000},
	} {
		if code, _ := e.do("POST", "/api/v2/invoices", key, body); code != http.StatusBadRequest {
			t.Fatalf("%v should be rejected, got %d", body, code)
		}
	}
	if code, _ := e.do("POST", "/api/v2/admin/merchants/mch_777_88/static-qris", "admin-secret", map[string]any{"static_qris": "bukan-qris"}); code != http.StatusBadRequest {
		t.Fatalf("invalid static QRIS must be rejected, got %d", code)
	}
}
