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

	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx"
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
`

// PostgresStore persists state in Postgres; sessions are encrypted with Cipher.
type PostgresStore struct {
	db     *sql.DB
	cipher *Cipher
}

// OpenPostgres connects and creates the tables if needed.
func OpenPostgres(ctx context.Context, dsn string, c *Cipher) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
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
	err := row.Scan(&m.ID, &m.Name, &m.ShopeeMerchantID, &m.StoreID, &m.StaticQris, &enc, &m.Status, &m.UpdatedAt)
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

const merchantCols = `id, name, shopee_merchant_id, store_id, static_qris, session_enc, status, updated_at`

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
	_, err := s.db.ExecContext(ctx, `insert into gateway_apps (id, name, merchant_id, key_hash) values ($1,$2,$3,$4)`,
		app.ID, app.Name, app.MerchantID, keyHash)
	return err
}

func (s *PostgresStore) AppByKeyHash(ctx context.Context, keyHash string) (App, error) {
	var a App
	err := s.db.QueryRowContext(ctx, `select id, name, merchant_id, created_at from gateway_apps where key_hash = $1`, keyHash).
		Scan(&a.ID, &a.Name, &a.MerchantID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (s *PostgresStore) ListApps(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, `select id, name, merchant_id, created_at from gateway_apps order by created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.MerchantID, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
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
