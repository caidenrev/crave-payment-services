package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Tes integrasi Postgres. Dilewati kecuali TEST_DATABASE_URL diisi.
// Jalankan ke CABANG database (mis. branch Neon), jangan ke database produksi:
//
//	TEST_DATABASE_URL=postgres://… go test ./ledger/ -run Postgres -v
//
// Tes membuat baris dengan ID acak lalu menghapusnya kembali.
func openTestPostgres(t *testing.T) (*PostgresStore, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL tidak diisi")
	}
	c, err := NewCipher(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := OpenPostgres(ctx, dsn, c)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Migrasi harus aman dijalankan berulang (tiap cold start serverless).
	if _, err := OpenPostgres(ctx, dsn, c); err != nil {
		t.Fatalf("second migrate must be a no-op: %v", err)
	}
	suffix := fmt.Sprintf("test_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`delete from gateway_checkout_tokens where invoice_id like '%' || $1`,
			`delete from gateway_invoices where id like '%' || $1`,
			`delete from gateway_checkout_themes where merchant_id like '%' || $1`,
			`delete from gateway_apps where id like '%' || $1`,
			`delete from gateway_merchants where id like '%' || $1`,
		} {
			if _, err := st.db.ExecContext(ctx, q, suffix); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
		_ = st.db.Close()
	})
	return st, suffix
}

func TestPostgresCheckout(t *testing.T) {
	st, sfx := openTestPostgres(t)
	ctx := context.Background()
	mID, appID, invID := "mch_"+sfx, "app_"+sfx, "inv_"+sfx
	now := time.Now().UTC().Truncate(time.Millisecond)

	if err := st.SaveMerchant(ctx, Merchant{ID: mID, Name: "Uji", Status: MerchantConnected}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateApp(ctx, App{ID: appID, Name: "Uji", MerchantID: mID, ClientKey: "pgk_pub_" + sfx}, "hash_"+sfx); err != nil {
		t.Fatal(err)
	}
	app, err := st.AppByID(ctx, appID)
	if err != nil || app.ClientKey != "pgk_pub_"+sfx {
		t.Fatalf("AppByID: %+v %v", app, err)
	}
	if byKey, err := st.AppByKeyHash(ctx, "hash_"+sfx); err != nil || byKey.ClientKey != app.ClientKey {
		t.Fatalf("AppByKeyHash must carry client key: %+v %v", byKey, err)
	}
	if err := st.SetClientKey(ctx, appID, "pgk_pub_new_"+sfx); err != nil {
		t.Fatal(err)
	}
	if err := st.SetClientKey(ctx, "app_tidakada_"+sfx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetClientKey unknown app: %v", err)
	}

	inv, _, err := st.CreateInvoice(ctx, Invoice{
		ID: invID, AppID: appID, MerchantID: mID, OrderID: "o", Amount: 1000, Status: StatusPending,
		QRString: "qr", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCheckoutToken(ctx, "tok_"+sfx, inv.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := st.InvoiceByToken(ctx, "tok_"+sfx, now)
	if err != nil || got.ID != invID {
		t.Fatalf("InvoiceByToken: %+v %v", got, err)
	}
	if _, err := st.InvoiceByToken(ctx, "tok_"+sfx, now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}
	if _, err := st.InvoiceByToken(ctx, "tok_tidakada_"+sfx, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}

	if ok, err := st.TryMarkChecked(ctx, invID, now, 3*time.Second); err != nil || !ok {
		t.Fatalf("first check: %v %v", ok, err)
	}
	if ok, _ := st.TryMarkChecked(ctx, invID, now.Add(time.Second), 3*time.Second); ok {
		t.Fatal("check within the gap must be refused")
	}
	if ok, _ := st.TryMarkChecked(ctx, invID, now.Add(3*time.Second), 3*time.Second); !ok {
		t.Fatal("check after the gap must pass")
	}

	if _, err := st.GetCheckoutTheme(ctx, mID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no theme yet: %v", err)
	}
	for _, theme := range []string{`{"brand_color":"#2D3FE7"}`, `{"brand_color":"#EA580C"}`} {
		if err := st.SaveCheckoutTheme(ctx, mID, []byte(theme)); err != nil {
			t.Fatal(err)
		}
	}
	if raw, err := st.GetCheckoutTheme(ctx, mID); err != nil || !strings.Contains(string(raw), "#EA580C") {
		t.Fatalf("theme upsert: %s %v", raw, err)
	}
}
