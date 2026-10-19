package ledger

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-process Store for tests and local runs. State is lost
// on restart, so it gives no protection across serverless instances.
type MemoryStore struct {
	mu        sync.Mutex
	claims    map[string]string
	merchants map[string]Merchant
	locks     map[string]*sync.Mutex
	apps      map[string]App
	keys      map[string]string // keyHash -> app id
	invoices  map[string]Invoice
	tokens    map[string]memToken // tokenHash -> token
	checked   map[string]time.Time
	themes    map[string][]byte
}

type memToken struct {
	invoiceID string
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		claims:    map[string]string{},
		merchants: map[string]Merchant{},
		locks:     map[string]*sync.Mutex{},
		apps:      map[string]App{},
		keys:      map[string]string{},
		invoices:  map[string]Invoice{},
		tokens:    map[string]memToken{},
		checked:   map[string]time.Time{},
		themes:    map[string][]byte{},
	}
}

func (s *MemoryStore) ClaimTransaction(_ context.Context, txID, ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.claims[txID]; ok {
		return owner, nil
	}
	s.claims[txID] = ref
	return ref, nil
}

func (s *MemoryStore) SaveMerchant(_ context.Context, m Merchant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.UpdatedAt = time.Now()
	s.merchants[m.ID] = m
	return nil
}

func (s *MemoryStore) GetMerchant(_ context.Context, id string) (Merchant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.merchants[id]
	if !ok {
		return Merchant{}, ErrNotFound
	}
	return m, nil
}

func (s *MemoryStore) ListMerchants(_ context.Context) ([]Merchant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Merchant, 0, len(s.merchants))
	for _, m := range s.merchants {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryStore) WithMerchantLock(ctx context.Context, id string, fn func(m *Merchant) error) error {
	s.mu.Lock()
	l, ok := s.locks[id]
	if !ok {
		l = &sync.Mutex{}
		s.locks[id] = l
	}
	s.mu.Unlock()

	l.Lock()
	defer l.Unlock()
	m, err := s.GetMerchant(ctx, id)
	if err != nil {
		return err
	}
	if err := fn(&m); err != nil {
		return err
	}
	return s.SaveMerchant(ctx, m)
}

func (s *MemoryStore) CreateApp(_ context.Context, app App, keyHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	app.CreatedAt = time.Now()
	s.apps[app.ID] = app
	s.keys[keyHash] = app.ID
	return nil
}

func (s *MemoryStore) AppByKeyHash(_ context.Context, keyHash string) (App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.keys[keyHash]
	if !ok {
		return App{}, ErrNotFound
	}
	return s.apps[id], nil
}

func (s *MemoryStore) AppByID(_ context.Context, id string) (App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[id]
	if !ok {
		return App{}, ErrNotFound
	}
	return a, nil
}

func (s *MemoryStore) SetClientKey(_ context.Context, appID, clientKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[appID]
	if !ok {
		return ErrNotFound
	}
	a.ClientKey = clientKey
	s.apps[appID] = a
	return nil
}

func (s *MemoryStore) ListApps(_ context.Context) ([]App, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]App, 0, len(s.apps))
	for _, a := range s.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryStore) CreateInvoice(_ context.Context, inv Invoice) (Invoice, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.invoices {
		if existing.AppID == inv.AppID && existing.OrderID == inv.OrderID {
			return existing, false, nil
		}
	}
	s.invoices[inv.ID] = inv
	return inv, true, nil
}

func (s *MemoryStore) GetInvoice(_ context.Context, appID, id string) (Invoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invoices[id]
	if !ok || inv.AppID != appID {
		return Invoice{}, ErrNotFound
	}
	return inv, nil
}

func (s *MemoryStore) MarkPaid(_ context.Context, id, txID, paymentType string, paidAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invoices[id]
	if !ok || inv.Status != StatusPending {
		return false, nil
	}
	inv.Status = StatusPaid
	inv.TransactionID = txID
	inv.PaymentType = paymentType
	inv.PaidAt = &paidAt
	s.invoices[id] = inv
	return true, nil
}

func (s *MemoryStore) MarkExpired(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invoices[id]
	if !ok || inv.Status != StatusPending {
		return false, nil
	}
	inv.Status = StatusExpired
	s.invoices[id] = inv
	return true, nil
}

func (s *MemoryStore) CreateCheckoutToken(_ context.Context, tokenHash, invoiceID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenHash] = memToken{invoiceID: invoiceID, expiresAt: expiresAt}
	return nil
}

func (s *MemoryStore) InvoiceByToken(_ context.Context, tokenHash string, now time.Time) (Invoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenHash]
	if !ok || !now.Before(t.expiresAt) {
		return Invoice{}, ErrNotFound
	}
	inv, ok := s.invoices[t.invoiceID]
	if !ok {
		return Invoice{}, ErrNotFound
	}
	return inv, nil
}

func (s *MemoryStore) TryMarkChecked(_ context.Context, invoiceID string, now time.Time, minGap time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.checked[invoiceID]; ok && last.After(now.Add(-minGap)) {
		return false, nil
	}
	s.checked[invoiceID] = now
	return true, nil
}

func (s *MemoryStore) GetCheckoutTheme(_ context.Context, merchantID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.themes[merchantID]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), t...), nil
}

func (s *MemoryStore) SaveCheckoutTheme(_ context.Context, merchantID string, theme []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.themes[merchantID] = append([]byte(nil), theme...)
	return nil
}
