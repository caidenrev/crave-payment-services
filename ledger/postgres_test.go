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
			// klaim merchant di tes ikut mengenai salinan merchant lain di branch: kembalikan dulu
			`update gateway_merchants set org_id = null where org_id like '%' || $1`,
			`delete from gateway_otp_sessions where id like '%' || $1`,
			`delete from gateway_org_members where org_id like '%' || $1`,
			`delete from gateway_orgs where id like '%' || $1`,
			`delete from gateway_webhook_events where app_id like '%' || $1`,
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

	// webhook: secret disimpan terenkripsi lalu terbaca utuh
	if err := st.SetWebhook(ctx, appID, "https://toko.id/hook", "whsec_"+sfx); err != nil {
		t.Fatal(err)
	}
	var rawSecret []byte
	if err := st.db.QueryRowContext(ctx, `select webhook_secret_enc from gateway_apps where id = $1`, appID).Scan(&rawSecret); err != nil ||
		strings.Contains(string(rawSecret), "whsec_") {
		t.Fatalf("webhook secret must be encrypted at rest: %v", err)
	}
	if a, err := st.AppByID(ctx, appID); err != nil || a.WebhookURL != "https://toko.id/hook" || a.WebhookSecret != "whsec_"+sfx {
		t.Fatalf("webhook roundtrip: %+v %v", a, err)
	}

	// sweep: TryMarkChecked terakhir di atas mencatat now+3s. Batas sesudahnya
	// mengambil tagihan; batas sebelumnya melewatinya.
	if c, err := st.SweepCandidates(ctx, now.Add(time.Minute), 100); err != nil || !containsInvoice(c, invID) {
		t.Fatalf("stale invoice must be a sweep candidate: %v", err)
	}
	if c, _ := st.SweepCandidates(ctx, now.Add(2*time.Second), 100); containsInvoice(c, invID) {
		t.Fatal("recently checked invoice must be skipped")
	}

	// antrean event: unik per (tagihan, jenis), lease, simpan hasil
	ev := WebhookEvent{ID: "evt_" + sfx, AppID: appID, InvoiceID: invID, Type: "invoice.paid", Payload: []byte(`{"a":1}`),
		Status: EventPending, NextAttemptAt: now, CreatedAt: now}
	if ok, err := st.EnqueueEvent(ctx, ev); err != nil || !ok {
		t.Fatalf("enqueue: %v %v", ok, err)
	}
	dup := ev
	dup.ID = "evt_dup_" + sfx
	if ok, err := st.EnqueueEvent(ctx, dup); err != nil || ok {
		t.Fatalf("duplicate (invoice,type) must be ignored: %v %v", ok, err)
	}
	leased, err := st.LeaseDueEvents(ctx, now, time.Minute, 100)
	if err != nil || !containsEvent(leased, ev.ID) {
		t.Fatalf("lease: %v", err)
	}
	if again, _ := st.LeaseDueEvents(ctx, now, time.Minute, 100); containsEvent(again, ev.ID) {
		t.Fatal("leased event must not be leased twice")
	}
	delivered := now.Add(time.Second)
	ev.Status, ev.Attempts, ev.DeliveredAt = EventDelivered, 1, &delivered
	if err := st.SaveEventAttempt(ctx, ev); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListEvents(ctx, appID, 10)
	if err != nil || len(list) != 1 || list[0].Status != EventDelivered || list[0].DeliveredAt == nil || string(list[0].Payload) != `{"a": 1}` {
		t.Fatalf("list events: %+v %v", list, err)
	}
}

func TestPostgresConsoleOrgs(t *testing.T) {
	st, sfx := openTestPostgres(t)
	ctx := context.Background()
	orgID, mA, mB := "org_"+sfx, "mch_a_"+sfx, "mch_b_"+sfx
	now := time.Now().UTC().Truncate(time.Millisecond)

	for _, id := range []string{mA, mB} {
		// dengan sesi: daftar console tidak boleh mendekripsinya
		if err := st.SaveMerchant(ctx, Merchant{ID: id, Name: id, Status: MerchantConnected, SessionJSON: []byte(`{"rahasia":1}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateOrg(ctx, Org{ID: orgID, Name: "Uji " + sfx}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMember(ctx, Membership{OrgID: orgID, UserID: "u_" + sfx, Email: "a@uji.id", Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	// upsert: peran & email berubah, tidak dobel
	if err := st.AddMember(ctx, Membership{OrgID: orgID, UserID: "u_" + sfx, Email: "b@uji.id", Role: RoleOwner}); err != nil {
		t.Fatal(err)
	}
	ms, err := st.MembershipsForUser(ctx, "u_"+sfx)
	if err != nil || len(ms) != 1 || ms[0].Role != RoleOwner || ms[0].Email != "b@uji.id" || ms[0].OrgName != "Uji "+sfx {
		t.Fatalf("memberships: %+v %v", ms, err)
	}

	if n, err := st.ClaimUnownedMerchants(ctx, orgID); err != nil || n < 2 {
		t.Fatalf("claim: %d %v", n, err)
	}
	// menyimpan ulang merchant (mis. login OTP ulang) tidak menghapus pemilik
	if err := st.SaveMerchant(ctx, Merchant{ID: mA, Name: "baru", Status: MerchantConnected}); err != nil {
		t.Fatal(err)
	}
	owned, err := st.MerchantsByOrg(ctx, orgID)
	var got []string
	for _, m := range owned {
		if m.ID == mA || m.ID == mB {
			got = append(got, m.ID)
			if m.OrgID != orgID || m.SessionJSON != nil {
				t.Fatalf("merchant org / session must not be loaded: %+v", m)
			}
		}
	}
	if err != nil || len(got) != 2 {
		t.Fatalf("merchants by org: %v %v", got, err)
	}

	// tagihan dua merchant (placeholder ganda) + batas waktu
	if err := st.CreateApp(ctx, App{ID: "app_" + sfx, Name: "Uji", MerchantID: mA}, "hash_"+sfx); err != nil {
		t.Fatal(err)
	}
	for i, c := range []struct {
		merchant string
		at       time.Time
	}{{mA, now}, {mB, now.Add(-time.Hour)}, {mA, now.Add(-100 * 24 * time.Hour)}} {
		inv := Invoice{ID: fmt.Sprintf("inv_%d_%s", i, sfx), AppID: "app_" + sfx, MerchantID: c.merchant, OrderID: fmt.Sprintf("o%d", i),
			Amount: 1000, Status: StatusPending, QRString: "qr", CreatedAt: c.at, ExpiresAt: c.at.Add(10 * time.Minute)}
		if _, _, err := st.CreateInvoice(ctx, inv); err != nil {
			t.Fatal(err)
		}
	}
	invs, err := st.InvoicesForMerchants(ctx, []string{mA, mB}, now.Add(-60*24*time.Hour), 100)
	if err != nil || len(invs) != 2 || invs[0].ID != "inv_0_"+sfx {
		t.Fatalf("invoices for merchants (newest first, 60 days): %+v %v", invs, err)
	}
	if none, err := st.InvoicesForMerchants(ctx, nil, now.Add(-time.Hour), 10); err != nil || len(none) != 0 {
		t.Fatalf("no merchants: %v %v", none, err)
	}
}

func TestPostgresConsoleManage(t *testing.T) {
	st, sfx := openTestPostgres(t)
	ctx := context.Background()
	orgA, orgB, mID, appID := "org_a_"+sfx, "org_b_"+sfx, "mch_"+sfx, "app_"+sfx
	now := time.Now().UTC()

	for _, o := range []string{orgA, orgB} {
		if err := st.CreateOrg(ctx, Org{ID: o, Name: o}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveMerchant(ctx, Merchant{ID: mID, Name: "Uji", Status: MerchantConnected}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.SetMerchantOrg(ctx, mID, orgA); err != nil || !ok {
		t.Fatalf("claim unowned: %v %v", ok, err)
	}
	if ok, _ := st.SetMerchantOrg(ctx, mID, orgB); ok {
		t.Fatal("merchant owned by another org must not be taken")
	}
	if ok, _ := st.SetMerchantOrg(ctx, mID, orgA); !ok {
		t.Fatal("re-claim by the owner is fine")
	}

	if err := st.CreateApp(ctx, App{ID: appID, Name: "Uji", MerchantID: mID, ClientKey: "pgk_pub_" + sfx}, "hash1_"+sfx); err != nil {
		t.Fatal(err)
	}
	if err := st.SetKeyHash(ctx, appID, "hash2_"+sfx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppByKeyHash(ctx, "hash1_"+sfx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old key must stop working: %v", err)
	}
	if err := st.RenameApp(ctx, appID, "Baru"); err != nil {
		t.Fatal(err)
	}
	if a, err := st.AppByKeyHash(ctx, "hash2_"+sfx); err != nil || a.Name != "Baru" {
		t.Fatalf("new key + rename: %+v %v", a, err)
	}
	if err := st.DeleteApp(ctx, appID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppByID(ctx, appID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted app must be invisible: %v", err)
	}
	if _, err := st.AppByKeyHash(ctx, "hash2_"+sfx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted app key must stop working: %v", err)
	}
	if err := st.DeleteApp(ctx, appID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}

	// sesi OTP: terenkripsi, sekali pakai, milik org+user, tetap dihitung untuk batas
	otp := OtpSession{ID: "otp_" + sfx, OrgID: orgA, UserID: "u_" + sfx, Kind: "challenge", Data: []byte(`{"cookie":"rahasia"}`), ExpiresAt: now.Add(10 * time.Minute)}
	if err := st.SaveOtpSession(ctx, otp); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := st.db.QueryRowContext(ctx, `select data_enc from gateway_otp_sessions where id = $1`, otp.ID).Scan(&raw); err != nil || strings.Contains(string(raw), "rahasia") {
		t.Fatalf("otp data must be encrypted at rest: %v", err)
	}
	if _, err := st.TakeOtpSession(ctx, otp.ID, orgB, otp.UserID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other org must not take it: %v", err)
	}
	got, err := st.TakeOtpSession(ctx, otp.ID, orgA, otp.UserID, now)
	if err != nil || string(got.Data) != `{"cookie":"rahasia"}` {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := st.TakeOtpSession(ctx, otp.ID, orgA, otp.UserID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("single use: %v", err)
	}
	if n, err := st.CountOtpSessions(ctx, otp.UserID, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("used session still counts for the rate limit: %d %v", n, err)
	}
	expired := OtpSession{ID: "otp_x_" + sfx, OrgID: orgA, UserID: otp.UserID, Kind: "challenge", Data: []byte("{}"), ExpiresAt: now.Add(-time.Minute)}
	_ = st.SaveOtpSession(ctx, expired)
	if _, err := st.TakeOtpSession(ctx, expired.ID, orgA, otp.UserID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
}

func containsInvoice(list []Invoice, id string) bool {
	for _, x := range list {
		if x.ID == id {
			return true
		}
	}
	return false
}

func containsEvent(list []WebhookEvent, id string) bool {
	for _, x := range list {
		if x.ID == id {
			return true
		}
	}
	return false
}
