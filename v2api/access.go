package v2api

// Permintaan akses dari landing page ("Minta akses").
//
//	POST /api/v2/public/access-requests        {name, email, phone, company, reason, website}
//	GET  /api/v2/console/access-requests       ?status=pending|approved|rejected (platform admin)
//	POST /api/v2/console/access-requests/{id}/approve  {org_name}
//	POST /api/v2/console/access-requests/{id}/reject
//
// Menyetujui permintaan membuat organisasi BARU milik pemohon lalu mengundangnya
// sebagai owner, jadi pemohon tidak pernah masuk ke organisasi founder.
// Platform admin = owner/admin organisasi yang owner-nya CONSOLE_BOOTSTRAP_EMAIL.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/utils"
)

const (
	accessPerIPHour = 3
	accessListLimit = 200
)

// AccessNotifier mengirim email pemberitahuan permintaan akses ke founder.
type AccessNotifier interface {
	Notify(ctx context.Context, subject, htmlBody, replyTo string) error
}

// resendNotifier memakai Resend HTTP API (RESEND_API_KEY).
type resendNotifier struct {
	apiKey, from, to string
	client           *http.Client
}

func (n resendNotifier) Notify(ctx context.Context, subject, htmlBody, replyTo string) error {
	payload := map[string]any{"from": n.from, "to": []string{n.to}, "subject": subject, "html": htmlBody}
	if replyTo != "" {
		payload["reply_to"] = replyTo
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("resend: HTTP %d %s", resp.StatusCode, body)
	}
	return nil
}

func (s *Server) accessNotifier() AccessNotifier {
	if s.Notifier != nil {
		return s.Notifier
	}
	to := s.NotifyEmail
	if to == "" {
		to = s.BootstrapEmail
	}
	if s.ResendAPIKey == "" || to == "" {
		return nil
	}
	from := s.EmailFrom
	if from == "" {
		from = "Crave Pay <no-reply@craveservices.my.id>"
	}
	return resendNotifier{apiKey: s.ResendAPIKey, from: from, to: to, client: &http.Client{Timeout: 6 * time.Second}}
}

// clientIP: IP pertama di X-Forwarded-For (Vercel), lalu X-Real-IP, lalu RemoteAddr.
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IP tidak disimpan mentah, hanya hash-nya (untuk batas kiriman).
func ipHash(ip string) string {
	sum := sha256.Sum256([]byte("access|" + ip))
	return hex.EncodeToString(sum[:16])
}

var phoneRe = regexp.MustCompile(`^\+?[0-9][0-9 \-]{6,18}[0-9]$`)

func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	return s, utf8.RuneCountInString(s) <= max
}

/* -------------------------------------------------------------- publik */

func (s *Server) routePublic(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && parts[0] == "access-requests" && r.Method == http.MethodPost {
		s.submitAccessRequest(w, r)
		return
	}
	writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint tidak ditemukan")
}

func (s *Server) submitAccessRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Phone   string `json:"phone"`
		Company string `json:"company"`
		Reason  string `json:"reason"`
		Website string `json:"website"` // jebakan bot: manusia tidak melihat kolom ini
	}
	if !decode(w, r, &req) {
		return
	}
	ok := map[string]any{"success": true, "status": ledger.AccessPending}
	if strings.TrimSpace(req.Website) != "" {
		writeJSON(w, http.StatusOK, ok) // pura-pura berhasil, tidak disimpan
		return
	}
	name, nameOK := cleanText(req.Name, 80)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	phone := strings.TrimSpace(req.Phone)
	company, companyOK := cleanText(req.Company, 100)
	reason, reasonOK := cleanText(req.Reason, 1000)
	switch {
	case utf8.RuneCountInString(name) < 2 || !nameOK:
		writeErr(w, http.StatusBadRequest, "INVALID_NAME", "Nama wajib diisi (2–80 karakter)")
		return
	case !validEmail(email):
		writeErr(w, http.StatusBadRequest, "INVALID_EMAIL", "Alamat email tidak valid")
		return
	case !phoneRe.MatchString(phone):
		writeErr(w, http.StatusBadRequest, "INVALID_PHONE", "Nomor HP / WhatsApp tidak valid")
		return
	case !companyOK:
		writeErr(w, http.StatusBadRequest, "INVALID_COMPANY", "Nama usaha maks. 100 karakter")
		return
	case utf8.RuneCountInString(reason) < 10 || !reasonOK:
		writeErr(w, http.StatusBadRequest, "INVALID_REASON", "Ceritakan kebutuhanmu (10–1000 karakter)")
		return
	}

	ctx := r.Context()
	now := s.Now().UTC()
	hash := ipHash(clientIP(r))
	if n, err := s.Store.CountAccessRequests(ctx, hash, now.Add(-time.Hour)); err == nil && n >= accessPerIPHour {
		writeErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "Terlalu banyak permintaan dari jaringan ini. Coba lagi dalam 1 jam.")
		return
	}
	// permintaan yang sama masih menunggu: jangan dobel, jangan kirim email lagi
	if _, err := s.Store.PendingAccessRequestByEmail(ctx, email); err == nil {
		writeJSON(w, http.StatusOK, ok)
		return
	}
	ar := ledger.AccessRequest{
		ID: "acr_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: name, Email: email, Phone: phone,
		Company: company, Reason: reason, IPHash: hash, CreatedAt: now,
	}
	if err := s.Store.CreateAccessRequest(ctx, ar); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan permintaan")
		return
	}
	if n := s.accessNotifier(); n != nil {
		nctx, cancel := detached(r, 6*time.Second)
		defer cancel()
		_ = n.Notify(nctx, "Permintaan akses Crave Pay: "+name, accessEmailHTML(ar), email) // tetap tersimpan walau email gagal
	}
	writeJSON(w, http.StatusCreated, ok)
}

func validEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && strings.Contains(email, ".")
}

func accessEmailHTML(ar ledger.AccessRequest) string {
	row := func(k, v string) string {
		if v == "" {
			v = "-"
		}
		return `<tr><td style="padding:6px 12px 6px 0;color:#64748B;font-size:13px;vertical-align:top;white-space:nowrap">` + k +
			`</td><td style="padding:6px 0;color:#0F172A;font-size:13px;font-weight:600">` + html.EscapeString(v) + `</td></tr>`
	}
	return `<div style="font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#F3F6FA;padding:28px 16px">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:20px;border:1px solid #E2E8F0;padding:28px">
<p style="margin:0 0 6px;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:#2D3FE7">Permintaan akses baru</p>
<h1 style="margin:0 0 16px;font-size:20px;color:#0F172A">` + html.EscapeString(ar.Name) + ` ingin memakai Crave Pay</h1>
<table role="presentation" cellpadding="0" cellspacing="0">` +
		row("Email", ar.Email) + row("HP / WA", ar.Phone) + row("Usaha", ar.Company) + `</table>
<p style="margin:16px 0 6px;font-size:12px;color:#64748B">Kebutuhan</p>
<p style="margin:0;padding:12px 14px;background:#F3F6FA;border-radius:12px;font-size:13px;line-height:1.6;color:#334155;white-space:pre-wrap">` + html.EscapeString(ar.Reason) + `</p>
<p style="margin:22px 0 0"><a href="https://pay.craveservices.my.id/dashboard" style="display:inline-block;background:#2D3FE7;color:#fff;text-decoration:none;font-weight:700;font-size:13px;padding:11px 20px;border-radius:12px">Tinjau di console (tab Tim)</a></p>
<p style="margin:16px 0 0;font-size:11.5px;color:#94A3B8">Balas email ini untuk menghubungi pemohon langsung.</p>
</div></div>`
}

/* ------------------------------------------------------------- console */

// isPlatformAdmin: owner/admin org yang owner-nya email founder.
func (s *Server) isPlatformAdmin(ctx context.Context, org ledger.Membership) bool {
	if s.BootstrapEmail == "" || (org.Role != ledger.RoleOwner && org.Role != ledger.RoleAdmin) {
		return false
	}
	ms, err := s.Store.MembersOfOrg(ctx, org.OrgID)
	if err != nil {
		return false
	}
	for _, m := range ms {
		if m.Role == ledger.RoleOwner && strings.EqualFold(m.Email, s.BootstrapEmail) {
			return true
		}
	}
	return false
}

func accessView(ar ledger.AccessRequest) map[string]any {
	v := map[string]any{
		"id": ar.ID, "name": ar.Name, "email": ar.Email, "phone": ar.Phone, "company": ar.Company,
		"reason": ar.Reason, "status": ar.Status, "created_at": ar.CreatedAt,
	}
	if !ar.DecidedAt.IsZero() {
		v["decided_at"] = ar.DecidedAt
		v["decided_by"] = ar.DecidedBy
	}
	return v
}

func (s *Server) routeAccessRequests(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser, rest []string) {
	if !s.isPlatformAdmin(r.Context(), org) {
		forbidden(w)
		return
	}
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		status := r.URL.Query().Get("status")
		if status != "" && status != ledger.AccessPending && status != ledger.AccessApproved && status != ledger.AccessRejected {
			writeErr(w, http.StatusBadRequest, "INVALID", "status tidak dikenal")
			return
		}
		list, err := s.Store.ListAccessRequests(r.Context(), status, accessListLimit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca permintaan akses")
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, ar := range list {
			out = append(out, accessView(ar))
		}
		_, invites := s.inviter()
		writeJSON(w, http.StatusOK, map[string]any{"requests": out, "invites_enabled": invites})
	case len(rest) == 2 && rest[1] == "approve" && r.Method == http.MethodPost:
		s.approveAccessRequest(w, r, user, rest[0])
	case len(rest) == 2 && rest[1] == "reject" && r.Method == http.MethodPost:
		s.rejectAccessRequest(w, r, user, rest[0])
	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint console tidak ditemukan")
	}
}

func (s *Server) pendingAccess(w http.ResponseWriter, r *http.Request, id string) (ledger.AccessRequest, bool) {
	ar, err := s.Store.GetAccessRequest(r.Context(), id)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Permintaan tidak ditemukan")
		return ar, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca permintaan")
		return ar, false
	}
	if ar.Status != ledger.AccessPending {
		writeErr(w, http.StatusConflict, "ALREADY_DECIDED", "Permintaan ini sudah "+map[string]string{ledger.AccessApproved: "disetujui", ledger.AccessRejected: "ditolak"}[ar.Status])
		return ar, false
	}
	return ar, true
}

func (s *Server) approveAccessRequest(w http.ResponseWriter, r *http.Request, user ConsoleUser, id string) {
	var req struct {
		OrgName string `json:"org_name"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	ar, ok := s.pendingAccess(w, r, id)
	if !ok {
		return
	}
	orgName, nameOK := cleanText(req.OrgName, 80)
	if orgName == "" {
		orgName = ar.Company
	}
	if orgName == "" {
		orgName = ar.Name
	}
	if !nameOK || utf8.RuneCountInString(orgName) > 80 {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nama organisasi maks. 80 karakter")
		return
	}
	inv, enabled := s.inviter()
	if !enabled {
		writeErr(w, http.StatusServiceUnavailable, "INVITES_DISABLED", "Undangan belum diaktifkan: SUPABASE_SERVICE_ROLE_KEY belum diatur di gateway")
		return
	}
	ctx, cancel := detached(r, 20*time.Second)
	defer cancel()
	userID, existing, err := inv.Invite(ctx, ar.Email, InviteData{OrgName: orgName, InvitedBy: user.Email, RoleLabel: roleLabels[ledger.RoleOwner]})
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errInviteRateLimited) {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, "INVITE_FAILED", err.Error())
		return
	}
	newOrg := ledger.Org{ID: "org_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: orgName}
	if err := s.Store.CreateOrg(ctx, newOrg); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membuat organisasi")
		return
	}
	if err := s.Store.AddMember(ctx, ledger.Membership{OrgID: newOrg.ID, UserID: userID, Email: ar.Email, Role: ledger.RoleOwner, InvitedBy: user.Email}); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menambahkan pemohon ke organisasi")
		return
	}
	if _, err := s.Store.DecideAccessRequest(ctx, ar.ID, ledger.AccessApproved, newOrg.ID, user.Email, s.Now().UTC()); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui permintaan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "org": map[string]any{"id": newOrg.ID, "name": newOrg.Name}, "email_sent": !existing})
}

func (s *Server) rejectAccessRequest(w http.ResponseWriter, r *http.Request, user ConsoleUser, id string) {
	ar, ok := s.pendingAccess(w, r, id)
	if !ok {
		return
	}
	if _, err := s.Store.DecideAccessRequest(r.Context(), ar.ID, ledger.AccessRejected, "", user.Email, s.Now().UTC()); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui permintaan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
