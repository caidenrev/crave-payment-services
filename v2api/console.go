package v2api

// API console (dashboard Crave Pay). Dipanggil dari browser dengan token login
// Supabase pengguna:
//
//	Authorization: Bearer <supabase access token>
//	X-Org-Id: org_…            (opsional bila pengguna hanya punya satu org)
//
//	GET /api/v2/console/me
//	GET /api/v2/console/merchants
//	GET /api/v2/console/apps
//	GET /api/v2/console/invoices?days=60
//
// Token diverifikasi ke Supabase (/auth/v1/user) memakai URL + anon key yang
// memang publik, jadi gateway tidak menyimpan secret Supabase. Hasilnya
// di-cache sebentar per token. Founder (CONSOLE_BOOTSTRAP_EMAIL) mendapat org
// pertama secara otomatis, berisi merchant yang belum dimiliki org mana pun.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/utils"
)

// ConsoleUser adalah pengguna console yang sudah terverifikasi.
type ConsoleUser struct {
	ID    string
	Email string
}

var errUnauthenticated = errors.New("unauthenticated")

const (
	consoleAuthCacheTTL  = time.Minute
	consoleInvoiceDays   = 60
	consoleInvoiceMaxDay = 90
	consoleInvoiceLimit  = 2000
	bootstrapOrgName     = "Crave Services"
)

type cachedUser struct {
	user    ConsoleUser
	expires time.Time
}

var (
	authCacheMu sync.Mutex
	authCache   = map[string]cachedUser{}
)

// verifySupabase menanyakan Supabase apakah token login masih sah.
func (s *Server) verifySupabase(ctx context.Context, token string) (ConsoleUser, error) {
	if s.SupabaseURL == "" || s.SupabaseAnonKey == "" {
		return ConsoleUser{}, errors.New("SUPABASE_URL / SUPABASE_ANON_KEY belum diatur")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	now := time.Now()
	authCacheMu.Lock()
	if c, ok := authCache[key]; ok && now.Before(c.expires) {
		authCacheMu.Unlock()
		return c.user, nil
	}
	authCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.SupabaseURL+"/auth/v1/user", nil)
	if err != nil {
		return ConsoleUser{}, err
	}
	req.Header.Set("apikey", s.SupabaseAnonKey)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ConsoleUser{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ConsoleUser{}, errUnauthenticated
	}
	if resp.StatusCode != http.StatusOK {
		return ConsoleUser{}, errors.New("supabase auth: HTTP " + strconv.Itoa(resp.StatusCode))
	}
	var body struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.ID == "" {
		return ConsoleUser{}, errUnauthenticated
	}
	user := ConsoleUser{ID: body.ID, Email: strings.ToLower(body.Email)}
	authCacheMu.Lock()
	if len(authCache) > 5000 { // batas sederhana supaya cache tidak tumbuh tanpa batas
		authCache = map[string]cachedUser{}
	}
	authCache[key] = cachedUser{user: user, expires: now.Add(consoleAuthCacheTTL)}
	authCacheMu.Unlock()
	return user, nil
}

func (s *Server) consoleUser(w http.ResponseWriter, r *http.Request) (ConsoleUser, bool) {
	tok := bearer(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "Login console wajib")
		return ConsoleUser{}, false
	}
	verify := s.ConsoleAuth
	if verify == nil {
		verify = s.verifySupabase
	}
	user, err := verify(r.Context(), tok)
	if errors.Is(err, errUnauthenticated) {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "Sesi login tidak valid atau sudah berakhir")
		return user, false
	}
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "Tidak bisa memverifikasi login saat ini")
		return user, false
	}
	return user, true
}

// memberships mengembalikan org pengguna; founder tanpa org dibuatkan org pertama.
func (s *Server) memberships(ctx context.Context, user ConsoleUser) ([]ledger.Membership, error) {
	ms, err := s.Store.MembershipsForUser(ctx, user.ID)
	if err != nil || len(ms) > 0 {
		return ms, err
	}
	if s.BootstrapEmail == "" || !strings.EqualFold(user.Email, s.BootstrapEmail) {
		return nil, nil
	}
	org := ledger.Org{ID: "org_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: bootstrapOrgName}
	if err := s.Store.CreateOrg(ctx, org); err != nil {
		return nil, err
	}
	if err := s.Store.AddMember(ctx, ledger.Membership{OrgID: org.ID, UserID: user.ID, Email: user.Email, Role: ledger.RoleOwner}); err != nil {
		return nil, err
	}
	if _, err := s.Store.ClaimUnownedMerchants(ctx, org.ID); err != nil {
		return nil, err
	}
	return s.Store.MembershipsForUser(ctx, user.ID)
}

// consoleOrg memilih org dari header X-Org-Id (wajib anggota), atau satu-satunya org pengguna.
func (s *Server) consoleOrg(w http.ResponseWriter, r *http.Request, user ConsoleUser) (ledger.Membership, bool) {
	ms, err := s.memberships(r.Context(), user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca organisasi")
		return ledger.Membership{}, false
	}
	want := strings.TrimSpace(r.Header.Get("X-Org-Id"))
	for _, m := range ms {
		if (want == "" && len(ms) == 1) || m.OrgID == want {
			return m, true
		}
	}
	if len(ms) == 0 {
		writeErr(w, http.StatusForbidden, "NO_ORG", "Akun ini belum tergabung di organisasi mana pun")
	} else {
		writeErr(w, http.StatusForbidden, "ORG_FORBIDDEN", "Pilih organisasi (X-Org-Id) yang kamu ikuti")
	}
	return ledger.Membership{}, false
}

func (s *Server) routeConsole(w http.ResponseWriter, r *http.Request, parts []string) {
	if r.Method != http.MethodGet || len(parts) != 1 {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint console tidak ditemukan")
		return
	}
	user, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if parts[0] == "me" {
		s.consoleMe(w, r, user)
		return
	}
	org, ok := s.consoleOrg(w, r, user)
	if !ok {
		return
	}
	switch parts[0] {
	case "merchants":
		s.consoleMerchants(w, r, org)
	case "apps":
		s.consoleApps(w, r, org)
	case "invoices":
		s.consoleInvoices(w, r, org)
	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint console tidak ditemukan")
	}
}

func (s *Server) consoleMe(w http.ResponseWriter, r *http.Request, user ConsoleUser) {
	ms, err := s.memberships(r.Context(), user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca organisasi")
		return
	}
	orgs := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		orgs = append(orgs, map[string]any{"id": m.OrgID, "name": m.OrgName, "role": m.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": map[string]any{"id": user.ID, "email": user.Email}, "orgs": orgs})
}

// orgApps mengembalikan aplikasi yang memakai merchant milik org.
func (s *Server) orgApps(ctx context.Context, merchants []ledger.Merchant) ([]ledger.App, error) {
	owned := map[string]bool{}
	for _, m := range merchants {
		owned[m.ID] = true
	}
	all, err := s.Store.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	var out []ledger.App
	for _, a := range all {
		if owned[a.MerchantID] {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *Server) consoleMerchants(w http.ResponseWriter, r *http.Request, org ledger.Membership) {
	ms, err := s.Store.MerchantsByOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	apps, err := s.orgApps(r.Context(), ms)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return
	}
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		var appList []map[string]any
		for _, a := range apps {
			if a.MerchantID == m.ID {
				appList = append(appList, map[string]any{"id": a.ID, "name": a.Name})
			}
		}
		view := merchantView(m)
		view["apps"] = appList
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"merchants": out})
}

func (s *Server) consoleApps(w http.ResponseWriter, r *http.Request, org ledger.Membership) {
	ms, err := s.Store.MerchantsByOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	apps, err := s.orgApps(r.Context(), ms)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return
	}
	out := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		// tanpa secret key maupun secret webhook
		out = append(out, map[string]any{
			"id": a.ID, "name": a.Name, "merchant_id": a.MerchantID, "client_key": a.ClientKey,
			"webhook_url": a.WebhookURL, "created_at": a.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

func (s *Server) consoleInvoices(w http.ResponseWriter, r *http.Request, org ledger.Membership) {
	days := consoleInvoiceDays
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d >= 1 && d <= consoleInvoiceMaxDay {
		days = d
	}
	ms, err := s.Store.MerchantsByOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.ID)
	}
	since := s.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	invs, err := s.Store.InvoicesForMerchants(r.Context(), ids, since, consoleInvoiceLimit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, inv := range invs {
		item := map[string]any{
			"id": inv.ID, "app_id": inv.AppID, "merchant_id": inv.MerchantID, "order_id": inv.OrderID,
			"amount": inv.Amount, "status": inv.Status, "created_at": inv.CreatedAt, "expires_at": inv.ExpiresAt,
		}
		if inv.PaidAt != nil {
			item["paid_at"] = *inv.PaidAt
			item["transaction_id"] = inv.TransactionID
			item["payment_type"] = inv.PaymentType
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"invoices": out, "days": days, "truncated": len(invs) == consoleInvoiceLimit})
}
