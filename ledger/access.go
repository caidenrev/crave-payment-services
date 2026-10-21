package ledger

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// Access request statuses.
const (
	AccessPending  = "pending"
	AccessApproved = "approved"
	AccessRejected = "rejected"
)

// AccessRequest is a public "minta akses" submission from the landing page.
// Approving one creates a new org for the requester and invites them as owner.
type AccessRequest struct {
	ID        string
	Name      string
	Email     string
	Phone     string
	Company   string
	Reason    string
	Status    string
	IPHash    string
	OrgID     string // set when approved
	DecidedBy string // email of the console user who approved/rejected
	CreatedAt time.Time
	DecidedAt time.Time
}

// AccessStore persists access requests. Both stores implement it.
type AccessStore interface {
	CreateAccessRequest(ctx context.Context, r AccessRequest) error
	GetAccessRequest(ctx context.Context, id string) (AccessRequest, error)
	// ListAccessRequests returns newest first; status "" = all.
	ListAccessRequests(ctx context.Context, status string, limit int) ([]AccessRequest, error)
	// PendingAccessRequestByEmail finds an open request for email (ErrNotFound if none).
	PendingAccessRequestByEmail(ctx context.Context, email string) (AccessRequest, error)
	// CountAccessRequests counts submissions from ipHash since (rate limit).
	CountAccessRequests(ctx context.Context, ipHash string, since time.Time) (int, error)
	// DecideAccessRequest moves a pending request to status; false if it was not pending.
	DecideAccessRequest(ctx context.Context, id, status, orgID, by string, at time.Time) (bool, error)
}

/* ------------------------------------------------------------ postgres */

const accessSchema = `
create table if not exists gateway_access_requests (
  id text primary key,
  name text not null,
  email text not null,
  phone text not null default '',
  company text not null default '',
  reason text not null default '',
  status text not null default 'pending',
  ip_hash text not null default '',
  org_id text not null default '',
  decided_by text not null default '',
  created_at timestamptz not null default now(),
  decided_at timestamptz
);
create index if not exists gateway_access_requests_created on gateway_access_requests (created_at desc);
create index if not exists gateway_access_requests_ip on gateway_access_requests (ip_hash, created_at);
`

const accessCols = `id, name, email, phone, company, reason, status, ip_hash, org_id, decided_by, created_at, coalesce(decided_at, 'epoch'::timestamptz)`

func scanAccess(row rowScanner) (AccessRequest, error) {
	var r AccessRequest
	err := row.Scan(&r.ID, &r.Name, &r.Email, &r.Phone, &r.Company, &r.Reason, &r.Status, &r.IPHash, &r.OrgID, &r.DecidedBy, &r.CreatedAt, &r.DecidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if r.DecidedAt.Unix() == 0 {
		r.DecidedAt = time.Time{}
	}
	return r, err
}

func (s *PostgresStore) CreateAccessRequest(ctx context.Context, r AccessRequest) error {
	_, err := s.db.ExecContext(ctx, `insert into gateway_access_requests (id, name, email, phone, company, reason, status, ip_hash, created_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.ID, r.Name, r.Email, r.Phone, r.Company, r.Reason, AccessPending, r.IPHash, r.CreatedAt)
	return err
}

func (s *PostgresStore) GetAccessRequest(ctx context.Context, id string) (AccessRequest, error) {
	return scanAccess(s.db.QueryRowContext(ctx, `select `+accessCols+` from gateway_access_requests where id = $1`, id))
}

func (s *PostgresStore) ListAccessRequests(ctx context.Context, status string, limit int) ([]AccessRequest, error) {
	rows, err := s.db.QueryContext(ctx, `select `+accessCols+` from gateway_access_requests
		where ($1 = '' or status = $1) order by created_at desc limit $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		r, err := scanAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) PendingAccessRequestByEmail(ctx context.Context, email string) (AccessRequest, error) {
	return scanAccess(s.db.QueryRowContext(ctx, `select `+accessCols+` from gateway_access_requests
		where lower(email) = lower($1) and status = 'pending' order by created_at desc limit 1`, email))
}

func (s *PostgresStore) CountAccessRequests(ctx context.Context, ipHash string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `select count(*) from gateway_access_requests where ip_hash = $1 and created_at >= $2`, ipHash, since).Scan(&n)
	return n, err
}

func (s *PostgresStore) DecideAccessRequest(ctx context.Context, id, status, orgID, by string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `update gateway_access_requests set status = $2, org_id = $3, decided_by = $4, decided_at = $5
		where id = $1 and status = 'pending'`, id, status, orgID, by, at)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

/* -------------------------------------------------------------- memory */

func (s *MemoryStore) CreateAccessRequest(_ context.Context, r AccessRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Status = AccessPending
	s.access[r.ID] = r
	return nil
}

func (s *MemoryStore) GetAccessRequest(_ context.Context, id string) (AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.access[id]
	if !ok {
		return r, ErrNotFound
	}
	return r, nil
}

func (s *MemoryStore) ListAccessRequests(_ context.Context, status string, limit int) ([]AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AccessRequest
	for _, r := range s.access {
		if status == "" || r.Status == status {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) PendingAccessRequestByEmail(_ context.Context, email string) (AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.access {
		if r.Status == AccessPending && strings.EqualFold(r.Email, email) {
			return r, nil
		}
	}
	return AccessRequest{}, ErrNotFound
}

func (s *MemoryStore) CountAccessRequests(_ context.Context, ipHash string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.access {
		if r.IPHash == ipHash && !r.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (s *MemoryStore) DecideAccessRequest(_ context.Context, id, status, orgID, by string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.access[id]
	if !ok || r.Status != AccessPending {
		return false, nil
	}
	r.Status, r.OrgID, r.DecidedBy, r.DecidedAt = status, orgID, by, at
	s.access[id] = r
	return true, nil
}
