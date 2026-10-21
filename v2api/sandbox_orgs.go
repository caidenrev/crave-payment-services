package v2api

// Organisasi buatan sendiri dan merchant sandbox.
//
//	POST /api/v2/console/orgs   {name}   → organisasi baru, pembuat jadi owner
//
// Merchant sandbox (id "mch_sandbox_<org>") dibuat otomatis saat aplikasi
// mode test dibuat tanpa merchant, supaya pengguna baru bisa mencoba integrasi
// sebelum menghubungkan ShopeePay. Hanya untuk aplikasi test.

import (
	"context"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/utils"
)

const (
	sandboxPrefix = "mch_sandbox_"
	maxOwnedOrgs  = 10
)

func isSandbox(merchantID string) bool { return strings.HasPrefix(merchantID, sandboxPrefix) }

// sandboxMerchant memastikan merchant sandbox org ada dan mengembalikan ID-nya.
func (s *Server) sandboxMerchant(ctx context.Context, org ledger.Membership) (string, *apiError) {
	id := sandboxPrefix + org.OrgID
	if m, err := s.Store.GetMerchant(ctx, id); err == nil && m.OrgID == org.OrgID {
		return id, nil
	}
	name := strings.TrimSpace(org.OrgName)
	if name == "" {
		name = "Toko"
	}
	m := ledger.Merchant{ID: id, Name: name + " (Sandbox)", Status: ledger.MerchantDisconnected}
	if err := s.Store.SaveMerchant(ctx, m); err != nil {
		return "", &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal membuat merchant sandbox"}
	}
	if ok, err := s.Store.SetMerchantOrg(ctx, id, org.OrgID); err != nil || !ok {
		return "", &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal menautkan merchant sandbox"}
	}
	return id, nil
}

// consoleCreateOrg: POST /api/v2/console/orgs (tidak butuh X-Org-Id).
func (s *Server) consoleCreateOrg(w http.ResponseWriter, r *http.Request, user ConsoleUser) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	name, ok := cleanText(req.Name, 80)
	if !ok || utf8.RuneCountInString(name) < 2 {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nama organisasi 2–80 karakter")
		return
	}
	ms, err := s.memberships(r.Context(), user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca organisasi")
		return
	}
	owned := 0
	for _, m := range ms {
		if m.Role == ledger.RoleOwner {
			owned++
		}
	}
	if owned >= maxOwnedOrgs {
		writeErr(w, http.StatusConflict, "ORG_LIMIT", "Maksimal 10 organisasi milikmu sendiri")
		return
	}
	org := ledger.Org{ID: "org_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: name}
	if err := s.Store.CreateOrg(r.Context(), org); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membuat organisasi")
		return
	}
	if err := s.Store.AddMember(r.Context(), ledger.Membership{OrgID: org.ID, UserID: user.ID, Email: user.Email, Role: ledger.RoleOwner, JoinedAt: s.Now().UTC()}); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menambahkan pemilik")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "org": map[string]any{"id": org.ID, "name": org.Name, "role": ledger.RoleOwner}})
}
