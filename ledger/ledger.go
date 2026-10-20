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
	// OrgID is the console organisation that owns the merchant ("" = belum dimiliki).
	OrgID     string
	UpdatedAt time.Time
}

// Console roles, from most to least privileged.
const (
	RoleOwner     = "owner"
	RoleAdmin     = "admin"
	RoleDeveloper = "developer"
	RoleViewer    = "viewer"
)

// Org is a console organisation; its members manage the org's merchants and apps.
type Org struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Membership links a console user (Supabase user id) to an org with a role.
type Membership struct {
	OrgID     string
	OrgName   string
	UserID    string
	Email     string
	Role      string
	CreatedAt time.Time
	// InvitedBy is the email of the member who sent the invite ("" for the founder).
	InvitedBy string
	// JoinedAt is when the user first opened the console as a member; zero = invited, not joined yet.
	JoinedAt time.Time
}

// App is a client application (a SaaS) allowed to bill through one merchant.
// Its secret API key is stored only as a hash; ClientKey is public (safe in a
// browser) and only opens checkout pages for tokens the app itself issued.
type App struct {
	ID         string
	Name       string
	MerchantID string
	ClientKey  string
	// WebhookURL menerima event tagihan; WebhookSecret (disimpan terenkripsi)
	// menandatangani setiap kiriman. Keduanya kosong = webhook mati.
	WebhookURL    string
	WebhookSecret string
	CreatedAt     time.Time
}

// Webhook event statuses.
const (
	EventPending   = "pending"
	EventDelivered = "delivered"
	EventFailed    = "failed"
)

// WebhookEvent is one notification queued for an app. (InvoiceID, Type) is
// unique, so a transition observed by several callers is sent once.
type WebhookEvent struct {
	ID            string
	AppID         string
	InvoiceID     string
	Type          string
	Payload       []byte
	Status        string
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	CreatedAt     time.Time
	DeliveredAt   *time.Time
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
	AppByID(ctx context.Context, id string) (App, error)
	ListApps(ctx context.Context) ([]App, error)
	// SetClientKey creates or replaces an app's public client key.
	SetClientKey(ctx context.Context, appID, clientKey string) error

	// CreateInvoice is idempotent per (AppID, OrderID): an existing invoice is
	// returned with created=false.
	CreateInvoice(ctx context.Context, inv Invoice) (out Invoice, created bool, err error)
	GetInvoice(ctx context.Context, appID, id string) (Invoice, error)
	// MarkPaid moves a pending invoice to paid; false if it was not pending.
	MarkPaid(ctx context.Context, id, txID, paymentType string, paidAt time.Time) (bool, error)
	MarkExpired(ctx context.Context, id string) (bool, error)

	// CreateCheckoutToken stores the hash of a token that opens one invoice's
	// checkout page until expiresAt. An invoice may have several tokens.
	CreateCheckoutToken(ctx context.Context, tokenHash, invoiceID string, expiresAt time.Time) error
	// InvoiceByToken returns the invoice a token opens, or ErrNotFound when the
	// token is unknown or expired at now.
	InvoiceByToken(ctx context.Context, tokenHash string, now time.Time) (Invoice, error)
	// TryMarkChecked records a feed check for an invoice. It returns false when
	// another check ran within minGap, so public polling cannot hammer Shopee.
	TryMarkChecked(ctx context.Context, invoiceID string, now time.Time, minGap time.Duration) (bool, error)

	// GetCheckoutTheme returns a merchant's checkout theme JSON, or ErrNotFound.
	GetCheckoutTheme(ctx context.Context, merchantID string) ([]byte, error)
	SaveCheckoutTheme(ctx context.Context, merchantID string, theme []byte) error

	// SetWebhook stores an app's webhook URL and signing secret ("" clears).
	SetWebhook(ctx context.Context, appID, url, secret string) error
	// EnqueueEvent stores ev; false when (InvoiceID, Type) was already queued.
	EnqueueEvent(ctx context.Context, ev WebhookEvent) (bool, error)
	// LeaseDueEvents returns pending events due at now and pushes their
	// NextAttemptAt to now+lease, so overlapping sweeps never send one twice.
	LeaseDueEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]WebhookEvent, error)
	// SaveEventAttempt records the outcome of a delivery attempt.
	SaveEventAttempt(ctx context.Context, ev WebhookEvent) error
	ListEvents(ctx context.Context, appID string, limit int) ([]WebhookEvent, error)
	// SweepCandidates returns pending invoices not checked since staleBefore.
	SweepCandidates(ctx context.Context, staleBefore time.Time, limit int) ([]Invoice, error)

	CreateOrg(ctx context.Context, org Org) error
	// AddMember adds a user to an org, or updates their role/email.
	AddMember(ctx context.Context, m Membership) error
	// MembershipsForUser returns the user's orgs (with OrgName), oldest first.
	MembershipsForUser(ctx context.Context, userID string) ([]Membership, error)
	// MembersOfOrg lists an org's members, oldest first.
	MembersOfOrg(ctx context.Context, orgID string) ([]Membership, error)
	// SetMemberRole changes a member's role; ErrNotFound when not a member.
	SetMemberRole(ctx context.Context, orgID, userID, role string) error
	// RemoveMember removes a user from an org; ErrNotFound when not a member.
	RemoveMember(ctx context.Context, orgID, userID string) error
	// MarkJoined records the first console visit of the user in every org they were invited to.
	MarkJoined(ctx context.Context, userID string, at time.Time) error
	// ClaimUnownedMerchants assigns every merchant without an org to orgID.
	ClaimUnownedMerchants(ctx context.Context, orgID string) (int, error)
	// MerchantsByOrg lists the org's merchants without their Shopee session.
	MerchantsByOrg(ctx context.Context, orgID string) ([]Merchant, error)
	// InvoicesForMerchants returns invoices of the merchants created since, newest first.
	InvoicesForMerchants(ctx context.Context, merchantIDs []string, since time.Time, limit int) ([]Invoice, error)

	// SetMerchantOrg gives an unowned merchant to orgID; false when another org owns it.
	SetMerchantOrg(ctx context.Context, merchantID, orgID string) (bool, error)
	// ReleaseMerchant removes a merchant from orgID: its Shopee session is wiped,
	// it becomes disconnected and unowned. False when orgID does not own it.
	ReleaseMerchant(ctx context.Context, merchantID, orgID string) (bool, error)
	// SetKeyHash replaces an app's secret key (the old key stops working at once).
	SetKeyHash(ctx context.Context, appID, keyHash string) error
	RenameApp(ctx context.Context, appID, name string) error
	// DeleteApp revokes an app: its keys and webhook stop working; invoices stay.
	// Deleted apps are invisible to AppByID, AppByKeyHash and ListApps.
	DeleteApp(ctx context.Context, appID string) error

	// SaveOtpSession stores encrypted intermediate Shopee login state for a console user.
	SaveOtpSession(ctx context.Context, s OtpSession) error
	// TakeOtpSession returns a session owned by org+user that has not expired and
	// marks it used (single use); ErrNotFound otherwise.
	TakeOtpSession(ctx context.Context, id, orgID, userID string, now time.Time) (OtpSession, error)
	// CountOtpSessions counts OTP challenges a user requested since (rate limit).
	CountOtpSessions(ctx context.Context, userID string, since time.Time) (int, error)
}

// OtpSession is short-lived Shopee login state (OTP challenge or verification)
// kept server-side so cookies/tokens never reach the browser. Data is plaintext
// here; stores encrypt it at rest.
type OtpSession struct {
	ID        string
	OrgID     string
	UserID    string
	Kind      string // "challenge" | "verification"
	Data      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
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
