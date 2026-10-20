package v2api

// Anggota tim organisasi: daftar, undang lewat email Supabase, ganti peran,
// keluarkan, dan kirim ulang undangan.
//
//	GET    /api/v2/console/members
//	POST   /api/v2/console/members                 {email, role}
//	PATCH  /api/v2/console/members/{user_id}       {role}
//	DELETE /api/v2/console/members/{user_id}
//	POST   /api/v2/console/members/{user_id}/resend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
)

// TeamInviter mengirim undangan login console. existing = akun sudah aktif
// (tidak ada email terkirim; cukup masuk seperti biasa).
type TeamInviter interface {
	Invite(ctx context.Context, email string) (userID string, existing bool, err error)
}

var errInviteRateLimited = errors.New("batas kirim email Supabase tercapai, coba lagi nanti")

// supabaseInviter memakai Supabase Auth Admin API dengan service role key.
type supabaseInviter struct {
	url, serviceKey string
	client          *http.Client
}

func (si supabaseInviter) call(ctx context.Context, path string, body any) (int, map[string]any, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, si.url+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("apikey", si.serviceKey)
	req.Header.Set("Authorization", "Bearer "+si.serviceKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := si.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out, nil
}

func (si supabaseInviter) Invite(ctx context.Context, email string) (string, bool, error) {
	code, out, err := si.call(ctx, "/auth/v1/invite", map[string]any{"email": email})
	if err != nil {
		return "", false, err
	}
	if code == http.StatusOK || code == http.StatusCreated {
		id, _ := out["id"].(string)
		if id == "" {
			return "", false, errors.New("Supabase tidak mengembalikan ID pengguna")
		}
		return id, false, nil
	}
	if code == http.StatusTooManyRequests {
		return "", false, errInviteRateLimited
	}
	// Akun sudah aktif: ambil ID-nya lewat generate_link (tidak mengirim email).
	if code == http.StatusUnprocessableEntity {
		code2, out2, err := si.call(ctx, "/auth/v1/admin/generate_link", map[string]any{"type": "magiclink", "email": email})
		if err != nil {
			return "", false, err
		}
		if id, _ := out2["id"].(string); code2 == http.StatusOK && id != "" {
			return id, true, nil
		}
	}
	msg, _ := out["msg"].(string)
	if msg == "" {
		msg, _ = out["error_description"].(string)
	}
	if msg == "" {
		msg = "Supabase menolak undangan"
	}
	return "", false, errors.New(msg)
}

func (s *Server) inviter() (TeamInviter, bool) {
	if s.Inviter != nil {
		return s.Inviter, true
	}
	if s.SupabaseURL == "" || s.SupabaseServiceKey == "" {
		return nil, false
	}
	return supabaseInviter{url: s.SupabaseURL, serviceKey: s.SupabaseServiceKey, client: &http.Client{Timeout: 15 * time.Second}}, true
}

var assignableRoles = map[string]bool{ledger.RoleOwner: true, ledger.RoleAdmin: true, ledger.RoleDeveloper: true, ledger.RoleViewer: true}

// canAssign: hanya owner yang boleh memberi/mengubah peran owner; admin
// mengelola admin, developer, dan viewer.
func canAssign(actor, target string) bool {
	switch actor {
	case ledger.RoleOwner:
		return true
	case ledger.RoleAdmin:
		return target != ledger.RoleOwner
	}
	return false
}

func memberView(m ledger.Membership) map[string]any {
	v := map[string]any{
		"user_id": m.UserID, "email": m.Email, "role": m.Role,
		"invited_by": m.InvitedBy, "invited_at": m.CreatedAt, "status": "active",
	}
	if m.JoinedAt.IsZero() {
		v["status"] = "invited"
	} else {
		v["joined_at"] = m.JoinedAt
	}
	return v
}

func (s *Server) routeMembers(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		s.listMembers(w, r, org)
	case len(rest) == 0 && r.Method == http.MethodPost:
		s.inviteMember(w, r, org, user)
	case len(rest) == 1 && r.Method == http.MethodPatch:
		s.changeMemberRole(w, r, org, user, rest[0])
	case len(rest) == 1 && r.Method == http.MethodDelete:
		s.removeMember(w, r, org, user, rest[0])
	case len(rest) == 2 && rest[1] == "resend" && r.Method == http.MethodPost:
		s.resendInvite(w, r, org, rest[0])
	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint console tidak ditemukan")
	}
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request, org ledger.Membership) {
	ms, err := s.Store.MembersOfOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca anggota")
		return
	}
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, memberView(m))
	}
	_, canInvite := s.inviter()
	writeJSON(w, http.StatusOK, map[string]any{"members": out, "invites_enabled": canInvite})
}

// findMember mengembalikan anggota org dan seluruh daftar (untuk cek owner terakhir).
func (s *Server) findMember(w http.ResponseWriter, r *http.Request, org ledger.Membership, userID string) (ledger.Membership, []ledger.Membership, bool) {
	ms, err := s.Store.MembersOfOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca anggota")
		return ledger.Membership{}, nil, false
	}
	for _, m := range ms {
		if m.UserID == userID {
			return m, ms, true
		}
	}
	writeErr(w, http.StatusNotFound, "NOT_FOUND", "Anggota tidak ditemukan")
	return ledger.Membership{}, nil, false
}

func ownerCount(ms []ledger.Membership) int {
	n := 0
	for _, m := range ms {
		if m.Role == ledger.RoleOwner {
			n++
		}
	}
	return n
}

func (s *Server) inviteMember(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser) {
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
		writeErr(w, http.StatusBadRequest, "INVALID_EMAIL", "Alamat email tidak valid")
		return
	}
	if !assignableRoles[req.Role] {
		writeErr(w, http.StatusBadRequest, "INVALID_ROLE", "Peran harus owner, admin, developer, atau viewer")
		return
	}
	if !canAssign(org.Role, req.Role) {
		forbidden(w)
		return
	}
	ms, err := s.Store.MembersOfOrg(r.Context(), org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca anggota")
		return
	}
	for _, m := range ms {
		if strings.EqualFold(m.Email, email) {
			writeErr(w, http.StatusConflict, "ALREADY_MEMBER", "Email ini sudah menjadi anggota organisasi")
			return
		}
	}
	inv, ok := s.inviter()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "INVITES_DISABLED", "Undangan belum diaktifkan: SUPABASE_SERVICE_ROLE_KEY belum diatur di gateway")
		return
	}
	ctx, cancel := detached(r, 20*time.Second)
	defer cancel()
	userID, existing, err := inv.Invite(ctx, email)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errInviteRateLimited) {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, "INVITE_FAILED", err.Error())
		return
	}
	m := ledger.Membership{OrgID: org.OrgID, UserID: userID, Email: email, Role: req.Role, InvitedBy: user.Email}
	if err := s.Store.AddMember(ctx, m); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan anggota")
		return
	}
	m.CreatedAt = s.Now().UTC()
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "member": memberView(m), "email_sent": !existing})
}

func (s *Server) changeMemberRole(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser, userID string) {
	var req struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !assignableRoles[req.Role] {
		writeErr(w, http.StatusBadRequest, "INVALID_ROLE", "Peran harus owner, admin, developer, atau viewer")
		return
	}
	if userID == user.ID {
		writeErr(w, http.StatusBadRequest, "SELF_ROLE", "Peranmu sendiri diubah oleh owner lain")
		return
	}
	target, ms, ok := s.findMember(w, r, org, userID)
	if !ok {
		return
	}
	if !canAssign(org.Role, target.Role) || !canAssign(org.Role, req.Role) {
		forbidden(w)
		return
	}
	if target.Role == ledger.RoleOwner && req.Role != ledger.RoleOwner && ownerCount(ms) <= 1 {
		writeErr(w, http.StatusConflict, "LAST_OWNER", "Organisasi harus punya minimal satu owner")
		return
	}
	if err := s.Store.SetMemberRole(r.Context(), org.OrgID, userID, req.Role); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal mengubah peran")
		return
	}
	target.Role = req.Role
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "member": memberView(target)})
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser, userID string) {
	target, ms, ok := s.findMember(w, r, org, userID)
	if !ok {
		return
	}
	// keluar sendiri selalu boleh; mengeluarkan orang lain mengikuti aturan peran
	if userID != user.ID && !canAssign(org.Role, target.Role) {
		forbidden(w)
		return
	}
	if target.Role == ledger.RoleOwner && ownerCount(ms) <= 1 {
		writeErr(w, http.StatusConflict, "LAST_OWNER", "Organisasi harus punya minimal satu owner")
		return
	}
	if err := s.Store.RemoveMember(r.Context(), org.OrgID, userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal mengeluarkan anggota")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) resendInvite(w http.ResponseWriter, r *http.Request, org ledger.Membership, userID string) {
	target, _, ok := s.findMember(w, r, org, userID)
	if !ok {
		return
	}
	if !canAssign(org.Role, target.Role) {
		forbidden(w)
		return
	}
	if !target.JoinedAt.IsZero() {
		writeErr(w, http.StatusConflict, "ALREADY_JOINED", "Anggota ini sudah aktif")
		return
	}
	inv, ok := s.inviter()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "INVITES_DISABLED", "Undangan belum diaktifkan: SUPABASE_SERVICE_ROLE_KEY belum diatur di gateway")
		return
	}
	ctx, cancel := detached(r, 20*time.Second)
	defer cancel()
	_, existing, err := inv.Invite(ctx, target.Email)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errInviteRateLimited) {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, "INVITE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "email_sent": !existing})
}
