package v2api

// Checkout (popup / halaman bayar), mengikuti pola Snap di Midtrans:
//
//	server  POST /api/v2/invoices (secret key)        → { …, token, redirect_url }
//	browser GET  /api/v2/checkout/{token}              (header X-Client-Key: pgk_pub_…)
//
// Client key bersifat publik: ia hanya bisa membuka tagihan lewat token yang
// diterbitkan untuk aplikasinya sendiri. Token disimpan sebagai hash, berlaku
// untuk satu tagihan, dan tidak pernah bisa membuat tagihan atau membaca data lain.
//
// Admin:
//
//	POST /api/v2/admin/apps/{id}/client-key            → buat/ganti client key
//	GET  /api/v2/admin/merchants/{id}/checkout-theme
//	PUT  /api/v2/admin/merchants/{id}/checkout-theme   {display_name, brand_color, …}

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hirotomasato/paygateme/ledger"
)

const (
	clientKeyPrefix = "pgk_pub_"
	tokenPrefix     = "ctk_"
	// Token tetap bisa dibuka sebentar setelah QR kedaluwarsa, supaya halaman
	// bayar menampilkan "lunas"/"kedaluwarsa" alih-alih "tidak ditemukan".
	checkoutViewGrace = time.Hour
	// Jeda minimal antar-pengecekan Shopee dari endpoint publik per tagihan.
	checkoutPollGap = 3 * time.Second
)

func randomKey(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newClientKey() (string, error) { return randomKey(clientKeyPrefix, 16) }

// issueCheckoutToken membuat token baru untuk tagihan. Tiap panggilan
// POST /invoices memberi token baru (yang lama tetap berlaku) karena token
// hanya disimpan sebagai hash dan tidak bisa ditampilkan ulang.
func (s *Server) issueCheckoutToken(ctx context.Context, inv ledger.Invoice) (string, error) {
	token, err := randomKey(tokenPrefix, 24)
	if err != nil {
		return "", err
	}
	if err := s.Store.CreateCheckoutToken(ctx, hashKey(token), inv.ID, inv.ExpiresAt.Add(checkoutViewGrace)); err != nil {
		return "", err
	}
	return token, nil
}

// addCheckout menambahkan token dan redirect_url ke respons buat tagihan.
// Kalau token gagal dibuat, tagihan tetap dikembalikan (integrasi lama tidak
// butuh token) dengan peringatan.
//
// redirect_url membawa client key aplikasi (?ck=) karena halaman bayar dibuka
// pelanggan tanpa kode integrasi apa pun; client key memang publik.
func (s *Server) addCheckout(ctx context.Context, view map[string]any, inv ledger.Invoice, app ledger.App) {
	token, err := s.issueCheckoutToken(ctx, inv)
	if err != nil {
		view["warning"] = "CHECKOUT_TOKEN_UNAVAILABLE"
		return
	}
	view["token"] = token
	switch {
	case s.CheckoutBaseURL == "":
	case app.ClientKey == "":
		// aplikasi lama: buat client key dulu lewat POST /admin/apps/{id}/client-key
		view["warning"] = "CLIENT_KEY_MISSING"
	default:
		view["redirect_url"] = s.CheckoutBaseURL + "/i/" + token + "?ck=" + url.QueryEscape(app.ClientKey)
	}
}

/* ------------------------------------------------------------ publik */

func (s *Server) publicCheckout(w http.ResponseWriter, r *http.Request, token string) {
	clientKey := strings.TrimSpace(r.Header.Get("X-Client-Key"))
	if clientKey == "" {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "Client key wajib (header X-Client-Key)")
		return
	}
	// Token tidak dikenal, kedaluwarsa, atau milik aplikasi lain dijawab sama:
	// 404, supaya tidak membocorkan bahwa token itu ada.
	notFound := func() {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Tagihan tidak ditemukan atau tautan sudah kedaluwarsa")
	}

	ctx := r.Context()
	now := s.Now().UTC()
	inv, err := s.Store.InvoiceByToken(ctx, hashKey(token), now)
	if errors.Is(err, ledger.ErrNotFound) {
		notFound()
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	app, err := s.Store.AppByID(ctx, inv.AppID)
	if err != nil || app.ClientKey == "" || subtle.ConstantTimeCompare([]byte(clientKey), []byte(app.ClientKey)) != 1 {
		notFound()
		return
	}

	if inv.Status == ledger.StatusPending {
		check, err := s.Store.TryMarkChecked(ctx, inv.ID, now, checkoutPollGap)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui tagihan")
			return
		}
		if check {
			updated, err := s.reconcile(ctx, inv)
			var gw *gatewayError
			switch {
			case err == nil:
				inv = updated
			case errors.As(err, &gw):
				// Shopee tidak bisa dihubungi: tetap pending, popup akan mencoba lagi
			default:
				writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui tagihan")
				return
			}
		}
	}

	out := map[string]any{
		"order_id": inv.OrderID, "amount": inv.Amount, "status": inv.Status,
		"created_at": inv.CreatedAt, "expires_at": inv.ExpiresAt,
		"merchant": map[string]any{"name": ""},
		"theme":    nil,
	}
	if inv.Status == ledger.StatusPending {
		out["qris_string"] = inv.QRString
	}
	if inv.PaidAt != nil {
		out["paid_at"] = *inv.PaidAt
	}
	if m, err := s.Store.GetMerchant(ctx, inv.MerchantID); err == nil {
		out["merchant"] = map[string]any{"name": m.Name}
	}
	if raw, err := s.Store.GetCheckoutTheme(ctx, inv.MerchantID); err == nil {
		out["theme"] = json.RawMessage(raw)
	}
	writeJSON(w, http.StatusOK, out)
}

/* ------------------------------------------------------------- admin */

func (s *Server) rollClientKey(w http.ResponseWriter, r *http.Request, appID string) {
	key, err := newClientKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat client key")
		return
	}
	err = s.Store.SetClientKey(r.Context(), appID, key)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Aplikasi tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan client key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": appID, "client_key": key})
}

// CheckoutTheme adalah tema popup/halaman bayar satu merchant. Disimpan
// setelah divalidasi, karena ditampilkan ke pelanggan di browser.
type CheckoutTheme struct {
	DisplayName string `json:"display_name"`
	LogoText    string `json:"logo_text"`
	LogoURL     string `json:"logo_url"`
	BrandColor  string `json:"brand_color"`
	Appearance  string `json:"appearance"`
	Corner      string `json:"corner"`
	Layout      string `json:"layout"`
	Headline    string `json:"headline"`
	ShowTimer   bool   `json:"show_timer"`
	ShowWallets bool   `json:"show_wallets"`
	ShowOrderID bool   `json:"show_order_id"`
	ShowCancel  bool   `json:"show_cancel"`
}

var hexColor = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func (t *CheckoutTheme) validate() error {
	t.DisplayName = strings.TrimSpace(t.DisplayName)
	t.LogoText = strings.TrimSpace(t.LogoText)
	t.LogoURL = strings.TrimSpace(t.LogoURL)
	t.Headline = strings.TrimSpace(t.Headline)
	switch {
	case utf8.RuneCountInString(t.DisplayName) > 40:
		return errors.New("display_name maks. 40 karakter")
	case utf8.RuneCountInString(t.LogoText) > 3:
		return errors.New("logo_text maks. 3 karakter")
	case utf8.RuneCountInString(t.Headline) > 50:
		return errors.New("headline maks. 50 karakter")
	case !hexColor.MatchString(t.BrandColor):
		return errors.New("brand_color harus kode hex, mis. #2D3FE7")
	case t.Appearance != "light" && t.Appearance != "dark":
		return errors.New("appearance harus light atau dark")
	case t.Corner != "sharp" && t.Corner != "rounded" && t.Corner != "pill":
		return errors.New("corner harus sharp, rounded, atau pill")
	case t.Layout != "popup" && t.Layout != "card":
		return errors.New("layout harus popup atau card")
	}
	if t.LogoURL != "" {
		u, err := url.Parse(t.LogoURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(t.LogoURL) > 500 {
			return errors.New("logo_url harus URL https:// yang valid (maks. 500 karakter)")
		}
	}
	return nil
}

func (s *Server) getCheckoutTheme(w http.ResponseWriter, r *http.Request, merchantID string) {
	raw, err := s.Store.GetCheckoutTheme(r.Context(), merchantID)
	if errors.Is(err, ledger.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"merchant_id": merchantID, "theme": nil})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tema")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"merchant_id": merchantID, "theme": json.RawMessage(raw)})
}

func (s *Server) putCheckoutTheme(w http.ResponseWriter, r *http.Request, merchantID string) {
	if _, err := s.Store.GetMerchant(r.Context(), merchantID); err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Merchant tidak ditemukan")
		return
	}
	var t CheckoutTheme
	if !decode(w, r, &t) {
		return
	}
	if err := t.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_THEME", err.Error())
		return
	}
	raw, _ := json.Marshal(t)
	if err := s.Store.SaveCheckoutTheme(r.Context(), merchantID, raw); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan tema")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "merchant_id": merchantID, "theme": t})
}
