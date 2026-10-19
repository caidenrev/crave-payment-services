// Package v2api serves /api/v2: the gateway owns the Shopee merchant session,
// client apps authenticate with an API key, and every settlement is recorded
// in the claim ledger so one ShopeePay transaction pays exactly one invoice.
//
// Admin routes (Authorization: Bearer $ADMIN_TOKEN):
//
//	POST /api/v2/admin/otp/request              {phone, password, channel}
//	POST /api/v2/admin/otp/verify               {challenge, otp, merchant_id, store_id, static_qris}
//	POST /api/v2/admin/otp/complete             {verification, merchant_id, store_id, static_qris}
//	GET  /api/v2/admin/merchants
//	POST /api/v2/admin/merchants/{id}/static-qris {static_qris}
//	GET  /api/v2/admin/apps
//	POST /api/v2/admin/apps                     {name, merchant_id}  → api_key (shown once) + client_key
//	POST /api/v2/admin/apps/{id}/client-key     → new client_key
//	GET  /api/v2/admin/merchants/{id}/checkout-theme
//	PUT  /api/v2/admin/merchants/{id}/checkout-theme
//
// App routes (Authorization: Bearer <api_key>, call from a server, never a browser):
//
//	GET  /api/v2/merchant
//	POST /api/v2/invoices                       {order_id, amount, expires_in_minutes} → … + token, redirect_url
//	GET  /api/v2/invoices/{id}
//
// Public checkout route (browser, X-Client-Key: <client_key>), see checkout.go:
//
//	GET  /api/v2/checkout/{token}
package v2api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hirotomasato/paygateme/core"
	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/qris"
	"github.com/hirotomasato/paygateme/shopee"
	"github.com/hirotomasato/paygateme/utils"
	"rsc.io/qr"
)

// ShopeeClient is the slice of the Shopee provider the API needs (fakeable in tests).
type ShopeeClient interface {
	Recent(ctx context.Context, start, end time.Time) ([]core.MerchantTransaction, error)
	Refresh(ctx context.Context) error
	Session() *shopee.Session
}

// Server holds the dependencies of /api/v2.
type Server struct {
	Store      ledger.Store
	AdminToken string
	NewClient  func(sess *shopee.Session) ShopeeClient
	Now        func() time.Time
	// CheckoutBaseURL membentuk redirect_url (mis. https://pay.craveservices.my.id);
	// kosong = redirect_url tidak dikirim.
	CheckoutBaseURL string
}

type providerClient struct{ p *shopee.Provider }

func (c providerClient) Recent(ctx context.Context, start, end time.Time) ([]core.MerchantTransaction, error) {
	return c.p.GetRecentTransactions(ctx, start, end)
}
func (c providerClient) Refresh(ctx context.Context) error {
	_, err := c.p.RefreshSession(ctx)
	return err
}
func (c providerClient) Session() *shopee.Session { return c.p.ExportSession() }

func newProviderClient(sess *shopee.Session) ShopeeClient {
	return providerClient{shopee.NewProvider(shopee.ProviderConfig{
		Session:      sess,
		DeviceReport: shopee.DeviceRiskBlob,
		Logger:       utils.NewConsoleLogger(utils.LevelInfo),
	})}
}

// Handle serves /api/v2 using the ledger configured by environment variables.
func Handle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	st, err := ledger.FromEnv(ctx)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "NOT_CONFIGURED", "API v2 belum dikonfigurasi: "+err.Error())
		return
	}
	s := &Server{
		Store: st, AdminToken: strings.TrimSpace(os.Getenv("ADMIN_TOKEN")), NewClient: newProviderClient, Now: time.Now,
		CheckoutBaseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("CHECKOUT_BASE_URL")), "/"),
	}
	s.ServeHTTP(w, r)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2"), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	switch {
	case path == "" || path == "/health":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": 2})

	case parts[0] == "admin":
		if !s.isAdmin(r) {
			writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "Token admin tidak valid")
			return
		}
		s.routeAdmin(w, r, parts[1:])

	case parts[0] == "checkout":
		if len(parts) != 2 || parts[1] == "" || r.Method != http.MethodGet {
			writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint tidak ditemukan")
			return
		}
		s.publicCheckout(w, r, parts[1])

	default:
		app, ok := s.authApp(w, r)
		if !ok {
			return
		}
		switch {
		case len(parts) == 1 && parts[0] == "merchant" && r.Method == http.MethodGet:
			s.getMerchant(w, r, app)
		case len(parts) == 1 && parts[0] == "invoices" && r.Method == http.MethodPost:
			s.createInvoice(w, r, app)
		case len(parts) == 2 && parts[0] == "invoices" && r.Method == http.MethodGet:
			s.getInvoice(w, r, app, parts[1])
		default:
			writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint tidak ditemukan")
		}
	}
}

/* ---------------------------------------------------------------- auth */

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) isAdmin(r *http.Request) bool {
	tok := bearer(r)
	// ADMIN_TOKEN kosong = rute admin dimatikan
	return s.AdminToken != "" && tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.AdminToken)) == 1
}

func (s *Server) authApp(w http.ResponseWriter, r *http.Request) (ledger.App, bool) {
	key := bearer(r)
	if key == "" {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "API key wajib (Authorization: Bearer <api_key>)")
		return ledger.App{}, false
	}
	app, err := s.Store.AppByKeyHash(r.Context(), hashKey(key))
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "API key tidak valid")
		return app, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memeriksa API key")
		return app, false
	}
	return app, true
}

/* --------------------------------------------------------------- admin */

func (s *Server) routeAdmin(w http.ResponseWriter, r *http.Request, parts []string) {
	switch {
	case len(parts) == 2 && parts[0] == "otp" && parts[1] == "request" && r.Method == http.MethodPost:
		s.otpRequest(w, r)
	case len(parts) == 2 && parts[0] == "otp" && parts[1] == "verify" && r.Method == http.MethodPost:
		s.otpVerify(w, r)
	case len(parts) == 2 && parts[0] == "otp" && parts[1] == "complete" && r.Method == http.MethodPost:
		s.otpComplete(w, r)
	case len(parts) == 1 && parts[0] == "merchants" && r.Method == http.MethodGet:
		s.listMerchants(w, r)
	case len(parts) == 3 && parts[0] == "merchants" && parts[2] == "static-qris" && r.Method == http.MethodPost:
		s.setStaticQris(w, r, parts[1])
	case len(parts) == 1 && parts[0] == "apps" && r.Method == http.MethodGet:
		s.listApps(w, r)
	case len(parts) == 1 && parts[0] == "apps" && r.Method == http.MethodPost:
		s.createApp(w, r)
	case len(parts) == 3 && parts[0] == "apps" && parts[2] == "client-key" && r.Method == http.MethodPost:
		s.rollClientKey(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "merchants" && parts[2] == "checkout-theme" && r.Method == http.MethodGet:
		s.getCheckoutTheme(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "merchants" && parts[2] == "checkout-theme" && r.Method == http.MethodPut:
		s.putCheckoutTheme(w, r, parts[1])
	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint admin tidak ditemukan")
	}
}

func (s *Server) otpRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
		Channel  int    `json:"channel"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Phone) == "" {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nomor telepon Shopee wajib diisi")
		return
	}
	logger := utils.NewConsoleLogger(utils.LevelInfo)
	auth := shopee.NewAuthClient(shopee.NewHTTPClient(logger), shopee.APILocale{}, logger)
	challenge, err := auth.RequestOtp(r.Context(), req.Phone, shopee.OtpRequestOptions{
		Password: req.Password, Channel: req.Channel, DeviceReport: shopee.DeviceRiskBlob,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "OTP_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "challenge": challenge})
}

func (s *Server) otpVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge  shopee.OtpChallenge `json:"challenge"`
		OTP        string              `json:"otp"`
		MerchantID string              `json:"merchant_id"`
		StoreID    string              `json:"store_id"`
		StaticQris string              `json:"static_qris"`
	}
	if !decode(w, r, &req) {
		return
	}
	provider := shopee.NewProvider(shopee.ProviderConfig{DeviceReport: shopee.DeviceRiskBlob, Logger: utils.NewConsoleLogger(utils.LevelInfo)})
	outcome, err := provider.LoginWithOtp(r.Context(), shopee.LoginWithOtpInput{
		Challenge: req.Challenge, OTP: req.OTP, MerchantID: req.MerchantID, StoreID: req.StoreID,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "OTP_FAILED", err.Error())
		return
	}
	if outcome.Status == shopee.LoginMerchantSelectionNeeded {
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true, "status": "MERCHANT_SELECTION_NEEDED",
			"merchants": outcome.Merchants, "verification": outcome.Verification,
		})
		return
	}
	if outcome.Session == nil {
		writeErr(w, http.StatusBadGateway, "NO_SESSION", "Login berhasil tetapi sesi tidak terbentuk")
		return
	}
	s.saveLoggedIn(w, r, provider, outcome.Session, req.StaticQris)
}

func (s *Server) otpComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Verification shopee.OtpVerification `json:"verification"`
		MerchantID   string                 `json:"merchant_id"`
		StoreID      string                 `json:"store_id"`
		StaticQris   string                 `json:"static_qris"`
	}
	if !decode(w, r, &req) {
		return
	}
	provider := shopee.NewProvider(shopee.ProviderConfig{DeviceReport: shopee.DeviceRiskBlob, Logger: utils.NewConsoleLogger(utils.LevelInfo)})
	session, err := provider.CompleteLogin(r.Context(), shopee.CompleteLoginInput{
		Verification: req.Verification, MerchantID: req.MerchantID, StoreID: req.StoreID,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "LOGIN_FAILED", err.Error())
		return
	}
	s.saveLoggedIn(w, r, provider, session, req.StaticQris)
}

func merchantKey(sess *shopee.Session) string {
	return "mch_" + sess.Merchant.ID + "_" + sess.StoreID
}

func (s *Server) saveLoggedIn(w http.ResponseWriter, r *http.Request, provider *shopee.Provider, session *shopee.Session, staticQris string) {
	if session.StoreID == "" {
		if stores, _ := provider.ListStores(r.Context()); len(stores) > 0 {
			if _, err := provider.SelectStore(r.Context(), stores[0].ID); err == nil {
				session = provider.ExportSession()
			}
		}
	}
	raw, err := json.Marshal(session)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SESSION_ENCODE", err.Error())
		return
	}
	m := ledger.Merchant{
		ID: merchantKey(session), Name: session.Merchant.Name, ShopeeMerchantID: session.Merchant.ID,
		StoreID: session.StoreID, SessionJSON: raw, Status: ledger.MerchantConnected,
	}
	if existing, err := s.Store.GetMerchant(r.Context(), m.ID); err == nil {
		m.StaticQris = existing.StaticQris // login ulang tidak menghapus QRIS statis yang sudah diatur
	}
	if q := strings.TrimSpace(staticQris); q != "" {
		if err := validateStatic(q); err != nil {
			writeErr(w, http.StatusBadRequest, "INVALID_QRIS", err.Error())
			return
		}
		m.StaticQris = q
	}
	if err := s.Store.SaveMerchant(r.Context(), m); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan merchant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "CONNECTED", "merchant": merchantView(m)})
}

func validateStatic(payload string) error {
	if _, err := qris.StaticToDynamicQris(payload, 1000); err != nil {
		return errors.New("QRIS statis tidak valid: " + err.Error())
	}
	return nil
}

func merchantView(m ledger.Merchant) map[string]any {
	return map[string]any{
		"id": m.ID, "name": m.Name, "shopee_merchant_id": m.ShopeeMerchantID, "store_id": m.StoreID,
		"status": m.Status, "static_qris_set": m.StaticQris != "", "updated_at": m.UpdatedAt,
	}
}

func (s *Server) listMerchants(w http.ResponseWriter, r *http.Request) {
	ms, err := s.Store.ListMerchants(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, merchantView(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"merchants": out})
}

func (s *Server) setStaticQris(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		StaticQris string `json:"static_qris"`
	}
	if !decode(w, r, &req) {
		return
	}
	q := strings.TrimSpace(req.StaticQris)
	if err := validateStatic(q); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_QRIS", err.Error())
		return
	}
	err := s.Store.WithMerchantLock(r.Context(), id, func(m *ledger.Merchant) error { m.StaticQris = q; return nil })
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Merchant tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan QRIS statis")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.Store.ListApps(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return
	}
	out := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		out = append(out, map[string]any{"id": a.ID, "name": a.Name, "merchant_id": a.MerchantID, "client_key": a.ClientKey, "created_at": a.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		MerchantID string `json:"merchant_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nama aplikasi wajib diisi")
		return
	}
	if _, err := s.Store.GetMerchant(r.Context(), req.MerchantID); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID", "merchant_id tidak ditemukan")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat API key")
		return
	}
	key := "pgk_" + base64.RawURLEncoding.EncodeToString(buf)
	clientKey, err := newClientKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat client key")
		return
	}
	app := ledger.App{ID: "app_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: strings.TrimSpace(req.Name), MerchantID: req.MerchantID, ClientKey: clientKey}
	if err := s.Store.CreateApp(r.Context(), app, hashKey(key)); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan aplikasi")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"app": map[string]any{"id": app.ID, "name": app.Name, "merchant_id": app.MerchantID},
		// hanya ditampilkan sekali; gateway menyimpan hash-nya saja
		"api_key": key,
		// publik, boleh di browser; selalu bisa dilihat lagi lewat GET /admin/apps
		"client_key": clientKey,
	})
}

/* ----------------------------------------------------------------- app */

func (s *Server) getMerchant(w http.ResponseWriter, r *http.Request, app ledger.App) {
	m, err := s.Store.GetMerchant(r.Context(), app.MerchantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"merchant": map[string]any{
		"name": m.Name, "status": m.Status, "static_qris_set": m.StaticQris != "",
	}})
}

func invoiceView(inv ledger.Invoice) map[string]any {
	out := map[string]any{
		"id": inv.ID, "order_id": inv.OrderID, "amount": inv.Amount, "status": inv.Status,
		"qris_string": inv.QRString, "created_at": inv.CreatedAt, "expires_at": inv.ExpiresAt,
	}
	if inv.PaidAt != nil {
		out["paid_at"] = *inv.PaidAt
		out["transaction_id"] = inv.TransactionID
		out["payment_type"] = inv.PaymentType
	}
	return out
}

func (s *Server) createInvoice(w http.ResponseWriter, r *http.Request, app ledger.App) {
	var req struct {
		OrderID          string `json:"order_id"`
		Amount           int64  `json:"amount"`
		ExpiresInMinutes int    `json:"expires_in_minutes"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.OrderID = strings.TrimSpace(req.OrderID)
	if req.OrderID == "" || len(req.OrderID) > 100 {
		writeErr(w, http.StatusBadRequest, "INVALID", "order_id wajib diisi (maks. 100 karakter)")
		return
	}
	if req.Amount < 1 || req.Amount > 100_000_000 {
		writeErr(w, http.StatusBadRequest, "INVALID", "amount harus antara 1 dan 100.000.000")
		return
	}
	expiry := 10
	if req.ExpiresInMinutes >= 1 && req.ExpiresInMinutes <= 60 {
		expiry = req.ExpiresInMinutes
	}

	m, err := s.Store.GetMerchant(r.Context(), app.MerchantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return
	}
	if m.Status != ledger.MerchantConnected {
		writeErr(w, http.StatusServiceUnavailable, "MERCHANT_DISCONNECTED", "Merchant terputus dari Shopee, admin perlu login OTP ulang")
		return
	}
	if m.StaticQris == "" {
		writeErr(w, http.StatusServiceUnavailable, "QRIS_NOT_SET", "QRIS statis merchant belum diatur")
		return
	}
	dynamic, err := qris.StaticToDynamicQris(m.StaticQris, req.Amount)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "QRIS_ERROR", err.Error())
		return
	}
	now := s.Now().UTC()
	inv, created, err := s.Store.CreateInvoice(r.Context(), ledger.Invoice{
		ID: "inv_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), AppID: app.ID, MerchantID: m.ID,
		OrderID: req.OrderID, Amount: req.Amount, Status: ledger.StatusPending, QRString: dynamic,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(expiry) * time.Minute),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan tagihan")
		return
	}
	if !created && inv.Amount != req.Amount {
		writeErr(w, http.StatusConflict, "ORDER_EXISTS", "order_id sudah dipakai dengan nominal berbeda")
		return
	}
	view := invoiceView(inv)
	if code, err := qr.Encode(inv.QRString, qr.M); err == nil {
		view["qris_image_base64"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	s.addCheckout(r.Context(), view, inv, app)
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, view)
}

func (s *Server) getInvoice(w http.ResponseWriter, r *http.Request, app ledger.App, id string) {
	inv, err := s.Store.GetInvoice(r.Context(), app.ID, id)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Tagihan tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	if inv.Status == ledger.StatusPending {
		updated, err := s.reconcile(r.Context(), inv)
		if err != nil {
			var gw *gatewayError
			if errors.As(err, &gw) {
				// tagihan tetap pending; klien boleh mencoba lagi
				view := invoiceView(inv)
				view["warning"] = gw.code
				writeJSON(w, http.StatusOK, view)
				return
			}
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui tagihan")
			return
		}
		inv = updated
	}
	writeJSON(w, http.StatusOK, invoiceView(inv))
}

type gatewayError struct{ code string }

func (e *gatewayError) Error() string { return e.code }

// reconcile reads the merchant feed (renewing the Shopee session if needed,
// under the merchant lock so concurrent polls never race on cookies) and
// settles the invoice through the claim ledger.
func (s *Server) reconcile(ctx context.Context, inv ledger.Invoice) (ledger.Invoice, error) {
	now := s.Now().UTC()
	var feed []core.MerchantTransaction
	var feedErr error

	err := s.Store.WithMerchantLock(ctx, inv.MerchantID, func(m *ledger.Merchant) error {
		if m.Status != ledger.MerchantConnected {
			feedErr = &gatewayError{"MERCHANT_DISCONNECTED"}
			return nil
		}
		var sess shopee.Session
		if err := json.Unmarshal(m.SessionJSON, &sess); err != nil {
			feedErr = &gatewayError{"SESSION_INVALID"}
			return nil
		}
		client := s.NewClient(&sess)
		start, end := inv.CreatedAt.Add(-time.Minute), now.Add(time.Minute)

		txs, err := client.Recent(ctx, start, end)
		if err != nil {
			// token merchant habis → perbarui tanpa OTP, lalu coba sekali lagi
			if rerr := client.Refresh(ctx); rerr != nil {
				if core.IsErrorCode(rerr, core.CodeAuthRequired) {
					m.Status = ledger.MerchantDisconnected
					feedErr = &gatewayError{"MERCHANT_DISCONNECTED"}
				} else {
					feedErr = &gatewayError{"SHOPEE_UNAVAILABLE"}
				}
			} else if txs, err = client.Recent(ctx, start, end); err != nil {
				feedErr = &gatewayError{"SHOPEE_UNAVAILABLE"}
			}
		}
		if renewed := client.Session(); renewed != nil {
			if raw, err := json.Marshal(renewed); err == nil && !bytes.Equal(raw, m.SessionJSON) {
				m.SessionJSON = raw // satu-satunya tempat sesi diperbarui
			}
		}
		feed = txs
		return nil
	})
	if err != nil {
		return inv, err
	}
	if feedErr != nil {
		// tetap boleh kedaluwarsa walau Shopee tidak bisa dihubungi
		if now.After(inv.ExpiresAt.Add(2 * time.Minute)) {
			if _, err := s.Store.MarkExpired(ctx, inv.ID); err != nil {
				return inv, err
			}
			return s.Store.GetInvoice(ctx, inv.AppID, inv.ID)
		}
		return inv, feedErr
	}
	return ledger.Settle(ctx, s.Store, inv, feed, now)
}

/* ------------------------------------------------------------- helpers */

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Body JSON tidak valid")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "code": code, "error": msg})
}
