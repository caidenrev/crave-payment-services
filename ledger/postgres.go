package ledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Tables are prefixed with gateway_ so the gateway can share a database with
// another app without colliding.
const schema = `
create table if not exists gateway_merchants (
  id text primary key,
  name text not null default '',
  shopee_merchant_id text not null default '',
  store_id text not null default '',
  static_qris text not null default '',
  session_enc bytea,
  status text not null default 'connected',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists gateway_apps (
  id text primary key,
  name text not null,
  merchant_id text not null references gateway_merchants(id),
  key_hash text not null unique,
  created_at timestamptz not null default now()
);
create table if not exists gateway_invoices (
  id text primary key,
  app_id text not null references gateway_apps(id),
  merchant_id text not null,
  order_id text not null,
  amount bigint not null check (amount > 0),
  status text not null,
  qris_string text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  paid_at timestamptz,
  transaction_id text,
  payment_type text,
  unique (app_id, order_id)
);
create index if not exists gateway_invoices_pending on gateway_invoices (merchant_id) where status = 'pending';
create table if not exists gateway_claims (
  transaction_id text primary key,
  ref text not null,
  claimed_at timestamptz not null default now()
);
alter table gateway_apps add column if not exists client_key text unique;
alter table gateway_invoices add column if not exists last_checked_at timestamptz;
create table if not exists gateway_checkout_tokens (
  token_hash text primary key,
  invoice_id text not null references gateway_invoices(id),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists gateway_checkout_tokens_invoice on gateway_checkout_tokens (invoice_id);
create table if not exists gateway_checkout_themes (
  merchant_id text primary key references gateway_merchants(id),
  theme jsonb not null,
  updated_at timestamptz not null default now()
);
alter table gateway_apps add column if not exists webhook_url text;
alter table gateway_apps add column if not exists webhook_secret_enc bytea;
create table if not exists gateway_webhook_events (
  id text primary key,
  app_id text not null references gateway_apps(id) on delete cascade,
  invoice_id text not null,
  type text not null,
  payload jsonb not null,
  status text not null default 'pending',
  attempts int not null default 0,
  next_attempt_at timestamptz not null,
  last_error text not null default '',
  created_at timestamptz not null default now(),
  delivered_at timestamptz,
  unique (invoice_id, type)
);
create index if not exists gateway_webhook_events_due on gateway_webhook_events (next_attempt_at) where status = 'pending';
create index if not exists gateway_invoices_sweep on gateway_invoices (created_at) where status = 'pending';
create table if not exists gateway_orgs (
  id text primary key,
  name text not null,
  created_at timestamptz not null default now()
);
create table if not exists gateway_org_members (
  org_id text not null references gateway_orgs(id) on delete cascade,
  user_id text not null,
  email text not null default '',
  role text not null,
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index if not exists gateway_org_members_user on gateway_org_members (user_id);
alter table gateway_merchants add column if not exists org_id text references gateway_orgs(id);
create index if not exists gateway_invoices_merchant_created on gateway_invoices (merchant_id, created_at desc);
alter table gateway_apps add column if not exists deleted_at timestamptz;
create table if not exists gateway_otp_sessions (
  id text primary key,
  org_id text not null,
  user_id text not null,
  kind text not null,
  data_enc bytea not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists gateway_otp_sessions_user on gateway_otp_sessions (user_id, created_at);
`

// PostgresStore persists state in Postgres; sessions are encrypted with Cipher.
type PostgresStore struct {
	db     *sql.DB
	cipher *Cipher
}

// OpenPostgres connects and creates the tables if needed.
func OpenPostgres(ctx context.Context, dsn string, c *Cipher) (*PostgresStore, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL tidak valid: %w", err)
	}
	// DATABASE_URL dari integrasi Neon melewati pooler (PgBouncer, transaction
	// mode): hindari prepared statement bernama yang terikat ke satu koneksi.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	db := stdlib.OpenDB(*cfg)
	// Serverless: each instance needs very few connections.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(30 * time.Second)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ledger migrate: %w", err)
	}
	return &PostgresStore{db: db, cipher: c}, nil
}

var (
	envOnce  sync.Mutex
	envStore Store
)

// FromEnv returns the shared Store configured by DATABASE_URL and
// SESSION_ENC_KEY, or nil (with the reason) when the ledger is not configured.
// A failed open is retried on the next call.
func FromEnv(ctx context.Context) (Store, error) {
	envOnce.Lock()
	defer envOnce.Unlock()
	if envStore != nil {
		return envStore, nil
	}
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	c, err := NewCipher(os.Getenv("SESSION_ENC_KEY"))
	if err != nil {
		return nil, err
	}
	st, err := OpenPostgres(ctx, dsn, c)
	if err != nil {
		return nil, err
	}
	envStore = st
	return envStore, nil
}

func (s *PostgresStore) ClaimTransaction(ctx context.Context, txID, ref string) (string, error) {
	// Insert-or-read in one statement: the primary key makes the first writer win.
	var owner string
	err := s.db.QueryRowContext(ctx, `
		with ins as (
		  insert into gateway_claims (transaction_id, ref) values ($1, $2)
		  on conflict (transaction_id) do nothing
		  returning ref
		)
		select ref from ins
		union all
		select ref from gateway_claims where transaction_id = $1
		limit 1`, txID, ref).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		// Kalah balapan dengan klaim bersamaan: baris pemenang belum terlihat oleh
		// snapshot statement tadi, jadi baca ulang dengan statement baru.
		err = s.db.QueryRowContext(ctx, `select ref from gateway_claims where transaction_id = $1`, txID).Scan(&owner)
	}
	return owner, err
}

func (s *PostgresStore) seal(m Merchant) ([]byte, error) {
	if len(m.SessionJSON) == 0 {
		return nil, nil
	}
	return s.cipher.Seal(m.SessionJSON)
}

func (s *PostgresStore) SaveMerchant(ctx context.Context, m Merchant) error {
	enc, err := s.seal(m)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		insert into gateway_merchants (id, name, shopee_merchant_id, store_id, static_qris, session_enc, status, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7, now())
		on conflict (id) do update set
		  name = excluded.name, shopee_merchant_id = excluded.shopee_merchant_id, store_id = excluded.store_id,
		  static_qris = excluded.static_qris, session_enc = excluded.session_enc, status = excluded.status, updated_at = now()`,
		m.ID, m.Name, m.ShopeeMerchantID, m.StoreID, m.StaticQris, enc, m.Status)
	return err
}

type rowScanner interface{ Scan(dest ...any) error }

func (s *PostgresStore) scanMerchant(row rowScanner) (Merchant, error) {
	var m Merchant
	var enc []byte
	err := row.Scan(&m.ID, &m.Name, &m.ShopeeMerchantID, &m.StoreID, &m.StaticQris, &enc, &m.Status, &m.OrgID, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	if err != nil {
		return m, err
	}
	if len(enc) > 0 {
		plain, err := s.cipher.Open(enc)
		if err != nil {
			return m, fmt.Errorf("decrypt session for %s: %w", m.ID, err)
		}
		m.SessionJSON = plain
	}
	return m, nil
}

const merchantCols = `id, name, shopee_merchant_id, store_id, static_qris, session_enc, status, coalesce(org_id,''), updated_at`

func (s *PostgresStore) GetMerchant(ctx context.Context, id string) (Merchant, error) {
	return s.scanMerchant(s.db.QueryRowContext(ctx, `select `+merchantCols+` from gateway_merchants where id = $1`, id))
}

func (s *PostgresStore) ListMerchants(ctx context.Context) ([]Merchant, error) {
	rows, err := s.db.QueryContext(ctx, `select `+merchantCols+` from gateway_merchants order by id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Merchant
	for rows.Next() {
		m, err := s.scanMerchant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) WithMerchantLock(ctx context.Context, id string, fn func(m *Merchant) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	m, err := s.scanMerchant(tx.QueryRowContext(ctx, `select `+merchantCols+` from gateway_merchants where id = $1 for update`, id))
	if err != nil {
		return err
	}
	if err := fn(&m); err != nil {
		return err
	}
	enc, err := s.seal(m)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `update gateway_merchants set session_enc = $2, status = $3, static_qris = $4, updated_at = now() where id = $1`,
		m.ID, enc, m.Status, m.StaticQris); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) CreateApp(ctx context.Context, app App, keyHash string) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_apps (id, name, merchant_id, key_hash, client_key) values ($1,$2,$3,$4, nullif($5,''))`,
		app.ID, app.Name, app.MerchantID, keyHash, app.ClientKey)
	return err
}

const appCols = `id, name, merchant_id, coalesce(client_key,''), coalesce(webhook_url,''), webhook_secret_enc, created_at`

func (s *PostgresStore) scanApp(row rowScanner) (App, error) {
	var a App
	var secretEnc []byte
	err := row.Scan(&a.ID, &a.Name, &a.MerchantID, &a.ClientKey, &a.WebhookURL, &secretEnc, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	if len(secretEnc) > 0 {
		plain, err := s.cipher.Open(secretEnc)
		if err != nil {
			return a, fmt.Errorf("decrypt webhook secret for %s: %w", a.ID, err)
		}
		a.WebhookSecret = string(plain)
	}
	return a, nil
}

func (s *PostgresStore) AppByKeyHash(ctx context.Context, keyHash string) (App, error) {
	return s.scanApp(s.db.QueryRowContext(ctx, `select `+appCols+` from gateway_apps where key_hash = $1 and deleted_at is null`, keyHash))
}

func (s *PostgresStore) AppByID(ctx context.Context, id string) (App, error) {
	return s.scanApp(s.db.QueryRowContext(ctx, `select `+appCols+` from gateway_apps where id = $1 and deleted_at is null`, id))
}

func (s *PostgresStore) ListApps(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, `select `+appCols+` from gateway_apps where deleted_at is null order by created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		a, err := s.scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetClientKey(ctx context.Context, appID, clientKey string) error {
	res, err := s.db.ExecContext(ctx, `update gateway_apps set client_key = $2 where id = $1`, appID, clientKey)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const invoiceCols = `id, app_id, merchant_id, order_id, amount, status, qris_string, created_at, expires_at, paid_at, coalesce(transaction_id,''), coalesce(payment_type,'')`

func scanInvoice(row rowScanner) (Invoice, error) {
	var inv Invoice
	var paid sql.NullTime
	err := row.Scan(&inv.ID, &inv.AppID, &inv.MerchantID, &inv.OrderID, &inv.Amount, &inv.Status, &inv.QRString,
		&inv.CreatedAt, &inv.ExpiresAt, &paid, &inv.TransactionID, &inv.PaymentType)
	if errors.Is(err, sql.ErrNoRows) {
		return inv, ErrNotFound
	}
	if paid.Valid {
		t := paid.Time
		inv.PaidAt = &t
	}
	return inv, err
}

func (s *PostgresStore) CreateInvoice(ctx context.Context, inv Invoice) (Invoice, bool, error) {
	res, err := s.db.ExecContext(ctx, `
		insert into gateway_invoices (id, app_id, merchant_id, order_id, amount, status, qris_string, created_at, expires_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		on conflict (app_id, order_id) do nothing`,
		inv.ID, inv.AppID, inv.MerchantID, inv.OrderID, inv.Amount, inv.Status, inv.QRString, inv.CreatedAt, inv.ExpiresAt)
	if err != nil {
		return inv, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return inv, true, nil
	}
	existing, err := scanInvoice(s.db.QueryRowContext(ctx,
		`select `+invoiceCols+` from gateway_invoices where app_id = $1 and order_id = $2`, inv.AppID, inv.OrderID))
	return existing, false, err
}

func (s *PostgresStore) GetInvoice(ctx context.Context, appID, id string) (Invoice, error) {
	return scanInvoice(s.db.QueryRowContext(ctx, `select `+invoiceCols+` from gateway_invoices where id = $1 and app_id = $2`, id, appID))
}

func (s *PostgresStore) MarkPaid(ctx context.Context, id, txID, paymentType string, paidAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_invoices set status = 'paid', transaction_id = $2, payment_type = $3, paid_at = $4
		where id = $1 and status = 'pending'`, id, txID, paymentType, paidAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *PostgresStore) MarkExpired(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_invoices set status = 'expired' where id = $1 and status = 'pending'`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *PostgresStore) CreateCheckoutToken(ctx context.Context, tokenHash, invoiceID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_checkout_tokens (token_hash, invoice_id, expires_at) values ($1,$2,$3)`,
		tokenHash, invoiceID, expiresAt)
	return err
}

func (s *PostgresStore) InvoiceByToken(ctx context.Context, tokenHash string, now time.Time) (Invoice, error) {
	return scanInvoice(s.db.QueryRowContext(ctx, `select `+invoiceCols+` from gateway_invoices
		where id = (select invoice_id from gateway_checkout_tokens where token_hash = $1 and expires_at > $2)`, tokenHash, now))
}

func (s *PostgresStore) TryMarkChecked(ctx context.Context, invoiceID string, now time.Time, minGap time.Duration) (bool, error) {
	// Satu statement: hanya satu pemanggil per jeda yang lolos, lintas instance serverless.
	res, err := s.db.ExecContext(ctx, `update gateway_invoices set last_checked_at = $2
		where id = $1 and (last_checked_at is null or last_checked_at <= $3)`, invoiceID, now, now.Add(-minGap))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *PostgresStore) GetCheckoutTheme(ctx context.Context, merchantID string) ([]byte, error) {
	var theme string
	err := s.db.QueryRowContext(ctx, `select theme::text from gateway_checkout_themes where merchant_id = $1`, merchantID).Scan(&theme)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return []byte(theme), err
}

func (s *PostgresStore) SetWebhook(ctx context.Context, appID, url, secret string) error {
	var enc []byte
	if secret != "" {
		var err error
		if enc, err = s.cipher.Seal([]byte(secret)); err != nil {
			return err
		}
	}
	res, err := s.db.ExecContext(ctx, `update gateway_apps set webhook_url = nullif($2,''), webhook_secret_enc = $3 where id = $1`, appID, url, enc)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const eventCols = `id, app_id, invoice_id, type, payload::text, status, attempts, next_attempt_at, last_error, created_at, delivered_at`

func scanEvent(row rowScanner) (WebhookEvent, error) {
	var ev WebhookEvent
	var payload string
	var delivered sql.NullTime
	err := row.Scan(&ev.ID, &ev.AppID, &ev.InvoiceID, &ev.Type, &payload, &ev.Status, &ev.Attempts,
		&ev.NextAttemptAt, &ev.LastError, &ev.CreatedAt, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return ev, ErrNotFound
	}
	ev.Payload = []byte(payload)
	if delivered.Valid {
		t := delivered.Time
		ev.DeliveredAt = &t
	}
	return ev, err
}

func scanEvents(rows *sql.Rows) ([]WebhookEvent, error) {
	defer rows.Close()
	var out []WebhookEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *PostgresStore) EnqueueEvent(ctx context.Context, ev WebhookEvent) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		insert into gateway_webhook_events (id, app_id, invoice_id, type, payload, status, next_attempt_at, created_at)
		values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8)
		on conflict (invoice_id, type) do nothing`,
		ev.ID, ev.AppID, ev.InvoiceID, ev.Type, string(ev.Payload), ev.Status, ev.NextAttemptAt, ev.CreatedAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *PostgresStore) LeaseDueEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]WebhookEvent, error) {
	// skip locked: dua sweep yang tumpang tindih mengambil event yang berbeda.
	rows, err := s.db.QueryContext(ctx, `
		update gateway_webhook_events set next_attempt_at = $2
		where id in (
		  select id from gateway_webhook_events
		  where status = 'pending' and next_attempt_at <= $1
		  order by next_attempt_at limit $3
		  for update skip locked)
		returning `+eventCols, now, now.Add(lease), limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

func (s *PostgresStore) SaveEventAttempt(ctx context.Context, ev WebhookEvent) error {
	_, err := s.db.ExecContext(ctx, `update gateway_webhook_events
		set status = $2, attempts = $3, next_attempt_at = $4, last_error = $5, delivered_at = $6 where id = $1`,
		ev.ID, ev.Status, ev.Attempts, ev.NextAttemptAt, ev.LastError, ev.DeliveredAt)
	return err
}

func (s *PostgresStore) ListEvents(ctx context.Context, appID string, limit int) ([]WebhookEvent, error) {
	rows, err := s.db.QueryContext(ctx, `select `+eventCols+` from gateway_webhook_events
		where app_id = $1 order by created_at desc limit $2`, appID, limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

func (s *PostgresStore) SweepCandidates(ctx context.Context, staleBefore time.Time, limit int) ([]Invoice, error) {
	rows, err := s.db.QueryContext(ctx, `select `+invoiceCols+` from gateway_invoices
		where status = 'pending' and (last_checked_at is null or last_checked_at < $1)
		order by created_at limit $2`, staleBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invoice
	for rows.Next() {
		inv, err := scanInvoice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateOrg(ctx context.Context, org Org) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_orgs (id, name) values ($1,$2)`, org.ID, org.Name)
	return err
}

func (s *PostgresStore) AddMember(ctx context.Context, m Membership) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_org_members (org_id, user_id, email, role) values ($1,$2,$3,$4)
		on conflict (org_id, user_id) do update set email = excluded.email, role = excluded.role`, m.OrgID, m.UserID, m.Email, m.Role)
	return err
}

func (s *PostgresStore) MembershipsForUser(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx, `select m.org_id, o.name, m.user_id, m.email, m.role, m.created_at
		from gateway_org_members m join gateway_orgs o on o.id = m.org_id
		where m.user_id = $1 order by m.created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.OrgID, &m.OrgName, &m.UserID, &m.Email, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ClaimUnownedMerchants(ctx context.Context, orgID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_merchants set org_id = $1 where org_id is null`, orgID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// merchantColsNoSession sama dengan merchantCols tanpa sesi Shopee: daftar untuk
// console tidak butuh (dan tidak boleh gagal karena) dekripsi sesi.
const merchantColsNoSession = `id, name, shopee_merchant_id, store_id, static_qris, null::bytea, status, coalesce(org_id,''), updated_at`

func (s *PostgresStore) MerchantsByOrg(ctx context.Context, orgID string) ([]Merchant, error) {
	rows, err := s.db.QueryContext(ctx, `select `+merchantColsNoSession+` from gateway_merchants where org_id = $1 order by name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Merchant
	for rows.Next() {
		m, err := s.scanMerchant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) InvoicesForMerchants(ctx context.Context, merchantIDs []string, since time.Time, limit int) ([]Invoice, error) {
	if len(merchantIDs) == 0 {
		return nil, nil
	}
	// placeholder eksplisit ($3, $4, …) supaya tidak bergantung pada encoding array
	args := []any{since, limit}
	ph := make([]string, len(merchantIDs))
	for i, id := range merchantIDs {
		args = append(args, id)
		ph[i] = fmt.Sprintf("$%d", i+3)
	}
	rows, err := s.db.QueryContext(ctx, `select `+invoiceCols+` from gateway_invoices
		where merchant_id in (`+strings.Join(ph, ",")+`) and created_at >= $1
		order by created_at desc limit $2`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invoice
	for rows.Next() {
		inv, err := scanInvoice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetMerchantOrg(ctx context.Context, merchantID, orgID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_merchants set org_id = $2 where id = $1 and (org_id is null or org_id = $2)`, merchantID, orgID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *PostgresStore) ReleaseMerchant(ctx context.Context, merchantID, orgID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_merchants set org_id = null, session_enc = null, status = $3, updated_at = now()
		where id = $1 and org_id = $2`, merchantID, orgID, MerchantDisconnected)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// execOne runs an update on a live (not deleted) app; ErrNotFound when none matched.
func (s *PostgresStore) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) SetKeyHash(ctx context.Context, appID, keyHash string) error {
	return s.execOne(ctx, `update gateway_apps set key_hash = $2 where id = $1 and deleted_at is null`, appID, keyHash)
}

func (s *PostgresStore) RenameApp(ctx context.Context, appID, name string) error {
	return s.execOne(ctx, `update gateway_apps set name = $2 where id = $1 and deleted_at is null`, appID, name)
}

func (s *PostgresStore) DeleteApp(ctx context.Context, appID string) error {
	// key_hash wajib unik & tidak null: ganti dengan penanda yang tidak cocok dengan key mana pun
	return s.execOne(ctx, `update gateway_apps set deleted_at = now(), key_hash = 'deleted:' || id,
		client_key = null, webhook_url = null, webhook_secret_enc = null
		where id = $1 and deleted_at is null`, appID)
}

func (s *PostgresStore) SaveOtpSession(ctx context.Context, o OtpSession) error {
	enc, err := s.cipher.Seal(o.Data)
	if err != nil {
		return err
	}
	// bersihkan sisa lama (lebih dari sehari) sambil lalu
	_, _ = s.db.ExecContext(ctx, `delete from gateway_otp_sessions where created_at < now() - interval '1 day'`)
	_, err = s.db.ExecContext(ctx, `insert into gateway_otp_sessions (id, org_id, user_id, kind, data_enc, expires_at) values ($1,$2,$3,$4,$5,$6)`,
		o.ID, o.OrgID, o.UserID, o.Kind, enc, o.ExpiresAt)
	return err
}

func (s *PostgresStore) TakeOtpSession(ctx context.Context, id, orgID, userID string, now time.Time) (OtpSession, error) {
	// update … returning dalam satu statement: sesi hanya bisa dipakai sekali.
	// Baris tetap disimpan (ditandai used_at) supaya batas permintaan OTP tetap terhitung.
	var o OtpSession
	var enc []byte
	err := s.db.QueryRowContext(ctx, `update gateway_otp_sessions set used_at = $4
		where id = $1 and org_id = $2 and user_id = $3 and expires_at > $4 and used_at is null
		returning id, org_id, user_id, kind, data_enc, expires_at, created_at`, id, orgID, userID, now).
		Scan(&o.ID, &o.OrgID, &o.UserID, &o.Kind, &enc, &o.ExpiresAt, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	if err != nil {
		return o, err
	}
	if o.Data, err = s.cipher.Open(enc); err != nil {
		return o, fmt.Errorf("decrypt otp session: %w", err)
	}
	return o, nil
}

func (s *PostgresStore) CountOtpSessions(ctx context.Context, userID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `select count(*) from gateway_otp_sessions where user_id = $1 and kind = 'challenge' and created_at >= $2`, userID, since).Scan(&n)
	return n, err
}

func (s *PostgresStore) SaveCheckoutTheme(ctx context.Context, merchantID string, theme []byte) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_checkout_themes (merchant_id, theme, updated_at) values ($1, $2::jsonb, now())
		on conflict (merchant_id) do update set theme = excluded.theme, updated_at = now()`, merchantID, string(theme))
	return err
}
