// Package ledger is the gateway's persistent memory: Shopee merchant sessions,
// client apps, invoices and — most importantly — the claim ledger that lets a
// ShopeePay transaction settle exactly one invoice.
//
// The legacy endpoints are stateless and match purely on amount, so a second
// invoice with the same amount (or an invoice in another app on the same
// merchant) could be "paid" by an earlier mutation. Every settlement now goes
// through ClaimTransaction, which is atomic across all callers.
package ledger

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/hirotomasato/paygateme/core"
	"github.com/hirotomasato/paygateme/payment"
)

var ErrNotFound = errors.New("not found")

// Invoice statuses.
const (
	StatusPending = "pending"
	StatusPaid    = "paid"
	StatusExpired = "expired"
)

// Merchant statuses.
const (
	MerchantConnected    = "connected"
	MerchantDisconnected = "disconnected"
)

// Merchant is a Shopee merchant store whose session the gateway owns.
type Merchant struct {
	ID               string
	Name             string
	ShopeeMerchantID string
	StoreID          string
	StaticQris       string
	// SessionJSON is the decrypted Shopee session (never returned to clients).
	SessionJSON []byte
	Status      string
	UpdatedAt   time.Time
}

// App is a client application (a SaaS) allowed to bill through one merchant.
type App struct {
	ID         string
	Name       string
	MerchantID string
	CreatedAt  time.Time
}

// Invoice is one QRIS bill.
type Invoice struct {
	ID            string
	AppID         string
	MerchantID    string
	OrderID       string
	Amount        int64
	Status        string
	QRString      string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	PaidAt        *time.Time
	TransactionID string
	PaymentType   string
}

// Store persists gateway state. Implementations must make ClaimTransaction
// atomic: concurrent callers claiming the same transaction id must observe a
// single owner.
type Store interface {
	// ClaimTransaction records that txID settles ref. It returns the owning ref:
	// equal to ref when this caller won (or already owned it), otherwise the ref
	// that claimed it first.
	ClaimTransaction(ctx context.Context, txID, ref string) (owner string, err error)

	SaveMerchant(ctx context.Context, m Merchant) error
	GetMerchant(ctx context.Context, id string) (Merchant, error)
	ListMerchants(ctx context.Context) ([]Merchant, error)
	// WithMerchantLock serialises work on one merchant (session renewal must
	// not race). Changes fn makes to SessionJSON/Status/StaticQris are saved.
	WithMerchantLock(ctx context.Context, id string, fn func(m *Merchant) error) error

	CreateApp(ctx context.Context, app App, keyHash string) error
	AppByKeyHash(ctx context.Context, keyHash string) (App, error)
	ListApps(ctx context.Context) ([]App, error)

	// CreateInvoice is idempotent per (AppID, OrderID): an existing invoice is
	// returned with created=false.
	CreateInvoice(ctx context.Context, inv Invoice) (out Invoice, created bool, err error)
	GetInvoice(ctx context.Context, appID, id string) (Invoice, error)
	// MarkPaid moves a pending invoice to paid; false if it was not pending.
	MarkPaid(ctx context.Context, id, txID, paymentType string, paidAt time.Time) (bool, error)
	MarkExpired(ctx context.Context, id string) (bool, error)
}

// Window bounds which transactions may settle a bill.
type Window struct {
	Amount    int64
	NotBefore time.Time
	NotAfter  time.Time
}

// eligible reports whether tx could pay for the window: same amount (gross or
// real gross), a completed status, and a known time inside the window.
// Transactions without a time are never auto-settled.
func (w Window) eligible(tx core.MerchantTransaction) bool {
	if tx.ID == "" || tx.Time.IsZero() {
		return false
	}
	if tx.Amount != w.Amount && (tx.RealAmount == 0 || tx.RealAmount != w.Amount) {
		return false
	}
	if !payment.IsSettledStatus(tx.Status) {
		return false
	}
	return !tx.Time.Before(w.NotBefore) && !tx.Time.After(w.NotAfter)
}

// ClaimFirst claims the oldest eligible, unclaimed transaction for ref and
// returns it, or nil when none is available. Transactions already owned by
// ref are returned again, so repeated polling is idempotent.
func ClaimFirst(ctx context.Context, st Store, ref string, w Window, txs []core.MerchantTransaction) (*core.MerchantTransaction, error) {
	candidates := make([]core.MerchantTransaction, 0, len(txs))
	for _, tx := range txs {
		if w.eligible(tx) {
			candidates = append(candidates, tx)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Time.Before(candidates[j].Time) })

	for i := range candidates {
		owner, err := st.ClaimTransaction(ctx, candidates[i].ID, ref)
		if err != nil {
			return nil, err
		}
		if owner == ref {
			return &candidates[i], nil
		}
	}
	return nil, nil
}

// InvoiceClockSkew tolerates small differences between Shopee's clock and ours.
const InvoiceClockSkew = 5 * time.Second

// Settle applies the feed to a pending invoice: claims a transaction and marks
// it paid, or expires it once its window has passed. The returned invoice
// reflects the stored state.
func Settle(ctx context.Context, st Store, inv Invoice, txs []core.MerchantTransaction, now time.Time) (Invoice, error) {
	if inv.Status != StatusPending {
		return inv, nil
	}
	tx, err := ClaimFirst(ctx, st, "inv:"+inv.ID, Window{
		Amount:    inv.Amount,
		NotBefore: inv.CreatedAt.Add(-InvoiceClockSkew),
		NotAfter:  inv.ExpiresAt.Add(2 * time.Minute),
	}, txs)
	if err != nil {
		return inv, err
	}
	if tx != nil {
		if _, err := st.MarkPaid(ctx, inv.ID, tx.ID, tx.PaymentType, tx.Time); err != nil {
			return inv, err
		}
		return st.GetInvoice(ctx, inv.AppID, inv.ID)
	}
	if now.After(inv.ExpiresAt) {
		if _, err := st.MarkExpired(ctx, inv.ID); err != nil {
			return inv, err
		}
		return st.GetInvoice(ctx, inv.AppID, inv.ID)
	}
	return inv, nil
}
