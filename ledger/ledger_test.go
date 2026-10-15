package ledger

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hirotomasato/paygateme/core"
)

var t0 = time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)

func tx(id string, amount int64, at time.Time) core.MerchantTransaction {
	return core.MerchantTransaction{ID: id, Amount: amount, Status: "completed", Time: at, PaymentType: "shopee:1"}
}

func newInvoice(t *testing.T, st *MemoryStore, id, app string, amount int64, created time.Time) Invoice {
	t.Helper()
	inv, created2, err := st.CreateInvoice(context.Background(), Invoice{
		ID: id, AppID: app, MerchantID: "m1", OrderID: "order-" + id, Amount: amount,
		Status: StatusPending, CreatedAt: created, ExpiresAt: created.Add(10 * time.Minute),
	})
	if err != nil || !created2 {
		t.Fatalf("create invoice %s: created=%v err=%v", id, created2, err)
	}
	return inv
}

func settle(t *testing.T, st *MemoryStore, inv Invoice, feed []core.MerchantTransaction, now time.Time) Invoice {
	t.Helper()
	out, err := Settle(context.Background(), st, inv, feed, now)
	if err != nil {
		t.Fatalf("settle %s: %v", inv.ID, err)
	}
	return out
}

// Bug yang dilaporkan: transaksi kedua bernominal sama langsung PAID memakai mutasi pertama.
func TestSecondInvoiceSameAmountIsNotPaidByOldMutation(t *testing.T) {
	st := NewMemoryStore()
	inv1 := newInvoice(t, st, "i1", "pos", 25000, t0)
	paid1 := tx("TX1", 25000, t0.Add(30*time.Second))
	if got := settle(t, st, inv1, []core.MerchantTransaction{paid1}, t0.Add(40*time.Second)); got.Status != StatusPaid || got.TransactionID != "TX1" {
		t.Fatalf("inv1 = %+v, want paid by TX1", got)
	}

	inv2 := newInvoice(t, st, "i2", "pos", 25000, t0.Add(20*time.Second)) // dibuat tak lama setelahnya
	if got := settle(t, st, inv2, []core.MerchantTransaction{paid1}, t0.Add(50*time.Second)); got.Status != StatusPending {
		t.Fatalf("inv2 must stay pending while only TX1 exists, got %s", got.Status)
	}
	paid2 := tx("TX2", 25000, t0.Add(90*time.Second))
	got := settle(t, st, inv2, []core.MerchantTransaction{paid2, paid1}, t0.Add(95*time.Second))
	if got.Status != StatusPaid || got.TransactionID != "TX2" {
		t.Fatalf("inv2 = %+v, want paid by TX2", got)
	}
}

// Dua aplikasi pada merchant yang sama, nominal sama, bersamaan.
func TestTwoAppsSameAmountEachGetOwnTransaction(t *testing.T) {
	st := NewMemoryStore()
	a := newInvoice(t, st, "a", "pos", 50000, t0)
	b := newInvoice(t, st, "b", "saas", 50000, t0.Add(5*time.Second))
	one := []core.MerchantTransaction{tx("TXA", 50000, t0.Add(60*time.Second))}

	ga := settle(t, st, a, one, t0.Add(61*time.Second))
	gb := settle(t, st, b, one, t0.Add(62*time.Second))
	if ga.Status != StatusPaid || gb.Status != StatusPending {
		t.Fatalf("one payment must settle one invoice: a=%s b=%s", ga.Status, gb.Status)
	}
	two := append(one, tx("TXB", 50000, t0.Add(120*time.Second)))
	gb = settle(t, st, b, two, t0.Add(121*time.Second))
	if gb.Status != StatusPaid || gb.TransactionID != "TXB" {
		t.Fatalf("b = %+v, want paid by TXB", gb)
	}
}

func TestRepeatedPollingIsIdempotent(t *testing.T) {
	st := NewMemoryStore()
	inv := newInvoice(t, st, "i", "pos", 10000, t0)
	feed := []core.MerchantTransaction{tx("TX", 10000, t0.Add(time.Minute))}
	first := settle(t, st, inv, feed, t0.Add(61*time.Second))
	again := settle(t, st, first, feed, t0.Add(70*time.Second))
	if again.Status != StatusPaid || again.TransactionID != "TX" || !again.PaidAt.Equal(*first.PaidAt) {
		t.Fatalf("second poll changed the invoice: %+v", again)
	}
	// Penanya lain (mis. endpoint lama) tidak bisa mengambil transaksi yang sama.
	if owner, _ := st.ClaimTransaction(context.Background(), "TX", "legacy:x"); owner != "inv:i" {
		t.Fatalf("TX owner = %s, want inv:i", owner)
	}
}

func TestRejectsFailedOldAndUntimedTransactions(t *testing.T) {
	st := NewMemoryStore()
	inv := newInvoice(t, st, "i", "pos", 15000, t0)
	failed := core.MerchantTransaction{ID: "F", Amount: 15000, Status: "shopee:2", Time: t0.Add(time.Minute)}
	old := tx("OLD", 15000, t0.Add(-time.Minute))
	untimed := core.MerchantTransaction{ID: "NT", Amount: 15000, Status: "completed"}
	other := tx("OTHER", 15001, t0.Add(time.Minute))
	got := settle(t, st, inv, []core.MerchantTransaction{failed, old, untimed, other}, t0.Add(2*time.Minute))
	if got.Status != StatusPending {
		t.Fatalf("no transaction should qualify, got %+v", got)
	}
	// Selisih jam kecil (≤5 detik sebelum tagihan dibuat) tetap diterima.
	skew := tx("SKEW", 15000, t0.Add(-3*time.Second))
	if got := settle(t, st, inv, []core.MerchantTransaction{skew}, t0.Add(time.Minute)); got.Status != StatusPaid {
		t.Fatalf("clock-skewed payment should settle, got %s", got.Status)
	}
}

func TestRealGrossAmountAlsoMatches(t *testing.T) {
	st := NewMemoryStore()
	inv := newInvoice(t, st, "i", "pos", 20000, t0)
	tr := core.MerchantTransaction{ID: "G", Amount: 19900, RealAmount: 20000, Status: "completed", Time: t0.Add(time.Minute)}
	if got := settle(t, st, inv, []core.MerchantTransaction{tr}, t0.Add(time.Minute)); got.Status != StatusPaid {
		t.Fatalf("real gross amount should match, got %s", got.Status)
	}
}

func TestExpiresAfterWindow(t *testing.T) {
	st := NewMemoryStore()
	inv := newInvoice(t, st, "i", "pos", 12000, t0)
	if got := settle(t, st, inv, nil, t0.Add(9*time.Minute)); got.Status != StatusPending {
		t.Fatalf("still within window, got %s", got.Status)
	}
	if got := settle(t, st, inv, nil, t0.Add(11*time.Minute)); got.Status != StatusExpired {
		t.Fatalf("want expired, got %s", got.Status)
	}
	// Pembayaran yang masuk tepat sebelum kedaluwarsa tetap diakui walau dicek sesudahnya.
	late := newInvoice(t, st, "late", "pos", 13000, t0)
	feed := []core.MerchantTransaction{tx("L", 13000, t0.Add(9*time.Minute+50*time.Second))}
	if got := settle(t, st, late, feed, t0.Add(11*time.Minute)); got.Status != StatusPaid {
		t.Fatalf("payment inside window must win over expiry, got %s", got.Status)
	}
}

func TestCreateInvoiceIsIdempotentPerApp(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	base := Invoice{ID: "x1", AppID: "pos", OrderID: "o-1", Amount: 1000, Status: StatusPending, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}
	if _, created, _ := st.CreateInvoice(ctx, base); !created {
		t.Fatal("first create must create")
	}
	dup := base
	dup.ID = "x2"
	got, created, _ := st.CreateInvoice(ctx, dup)
	if created || got.ID != "x1" {
		t.Fatalf("same order must return existing invoice, got %+v created=%v", got, created)
	}
	other := base
	other.ID, other.AppID = "x3", "saas"
	if _, created, _ := st.CreateInvoice(ctx, other); !created {
		t.Fatal("same order id in another app is a different invoice")
	}
}

func TestConcurrentClaimsHaveSingleOwner(t *testing.T) {
	st := NewMemoryStore()
	var wg sync.WaitGroup
	owners := make(chan string, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := "r" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			owner, _ := st.ClaimTransaction(context.Background(), "SAME", ref)
			if owner == ref {
				owners <- ref
			}
		}(i)
	}
	wg.Wait()
	close(owners)
	if n := len(owners); n != 1 {
		t.Fatalf("%d callers won the same transaction", n)
	}
}

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // 32 byte base64
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := c.Seal([]byte(`{"cookies":[]}`))
	plain, err := c.Open(sealed)
	if err != nil || string(plain) != `{"cookies":[]}` {
		t.Fatalf("round trip failed: %s %v", plain, err)
	}
	other, _ := NewCipher("ff31323334353637383961626364656630313233343536373839616263646566") // hex, beda kunci
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
	if _, err := NewCipher("pendek"); err == nil {
		t.Fatal("short key must be rejected")
	}
}
