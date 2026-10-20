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
//	PUT  /api/v2/admin/apps/{id}/webhook        {url} → webhook_secret (lihat webhook.go)
//	POST /api/v2/admin/apps/{id}/webhook/secret → secret baru
//	POST /api/v2/admin/apps/{id}/webhook/test   → kirim event "ping"
//	GET  /api/v2/admin/apps/{id}/webhook/events
//
// Console (Authorization: Bearer <token login Supabase>), lihat console.go:
//
//	GET  /api/v2/console/me | merchants | apps | invoices
//
// Cron (Authorization: Bearer $CRON_SECRET), dipanggil tiap menit oleh cron-job.org:
//
//	POST /api/v2/internal/sweep
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
	// CronSecret melindungi POST /api/v2/internal/sweep; kosong = sweep mati.
	CronSecret string
	// Webhooks mengirim HTTP ke server toko (bisa diganti di tes).
	Webhooks HTTPDoer
	// AllowInsecureWebhooks mengizinkan URL http/localhost (hanya untuk tes).
	AllowInsecureWebhooks bool
	// SupabaseURL + SupabaseAnonKey (publik) memverifikasi login console.
	SupabaseURL     string
	SupabaseAnonKey string
	// BootstrapEmail mendapat org pertama otomatis saat pertama membuka console.
	BootstrapEmail string
	// ConsoleAuth mengganti verifikasi Supabase (untuk tes); nil = Supabase.
	ConsoleAuth func(ctx context.Context, token string) (ConsoleUser, error)
	// Login mengganti login OTP Shopee (untuk tes); nil = Shopee sungguhan.
	Login ShopeeLogin
	// SupabaseServiceKey (rahasia) dipakai hanya untuk mengirim undangan anggota tim.
	SupabaseServiceKey string
	// Inviter mengganti pengirim undangan Supabase (untuk tes); nil = Supabase.
	Inviter TeamInviter
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
	timeout := 8 * time.Second
	if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/internal/sweep") {
		timeout = sweepBudget + sweepSendTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	r = r.WithContext(ctx)
	st, err := ledger.FromEnv(ctx)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "NOT_CONFIGURED", "API v2 belum dikonfigurasi: "+err.Error())
		return
	}
	s := &Server{
		Store: st, AdminToken: strings.TrimSpace(os.Getenv("ADMIN_TOKEN")), NewClient: newProviderClient, Now: time.Now,
		CheckoutBaseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("CHECKOUT_BASE_URL")), "/"),
		CronSecret:      strings.TrimSpace(os.Getenv("CRON_SECRET")),
		Webhooks:        defaultWebhookClient,
		SupabaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("SUPABASE_URL")), "/"),
		SupabaseAnonKey: strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY")),
		BootstrapEmail:  strings.TrimSpace(os.Getenv("CONSOLE_BOOTSTRAP_EMAIL")),

		SupabaseServiceKey: strings.TrimSpace(os.Getenv("SUPABASE_SERVICE_ROLE_KEY")),
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

	case parts[0] == "console":
		s.routeConsole(w, r, parts[1:])

	case parts[0] == "internal":
		if len(parts) != 2 || parts[1] != "sweep" || r.Method != http.MethodPost {
			writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint tidak ditemukan")
			return
		}
		s.sweep(w, r)

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
	case len(parts) == 3 && parts[0] == "apps" && parts[2] == "webhook" && r.Method == http.MethodPut:
		s.putWebhook(w, r, parts[1])
	case len(parts) == 4 && parts[0] == "apps" && parts[2] == "webhook" && parts[3] == "secret" && r.Method == http.MethodPost:
		s.rotateWebhookSecret(w, r, parts[1])
	case len(parts) == 4 && parts[0] == "apps" && parts[2] == "webhook" && parts[3] == "test" && r.Method == http.MethodPost:
		s.testWebhook(w, r, parts[1])
	case len(parts) == 4 && parts[0] == "apps" && parts[2] == "webhook" && parts[3] == "events" && r.Method == http.MethodGet:
		s.listWebhookEvents(w, r, parts[1])
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
	m, apiErr := s.persistMerchant(r.Context(), session, staticQris, "")
	if apiErr != nil {
		apiErr.write(w)
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
		out = append(out, map[string]any{
			"id": a.ID, "name": a.Name, "merchant_id": a.MerchantID, "client_key": a.ClientKey,
			"webhook_url": a.WebhookURL, "created_at": a.CreatedAt,
		})
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
	if _, err := s.Store.GetMerchant(r.Context(), req.MerchantID); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID", "merchant_id tidak ditemukan")
		return
	}
	app, key, apiErr := s.newApp(r.Context(), req.Name, req.MerchantID)
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusCreated, newAppResponse(app, key))
}

func newSecretKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "pgk_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// newApp membuat aplikasi baru untuk merchant beserta secret key & client key.
func (s *Server) newApp(ctx context.Context, name, merchantID string) (ledger.App, string, *apiError) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 60 {
		return ledger.App{}, "", &apiError{http.StatusBadRequest, "INVALID", "Nama aplikasi wajib diisi (maks. 60 karakter)"}
	}
	key, err := newSecretKey()
	if err != nil {
		return ledger.App{}, "", &apiError{http.StatusInternalServerError, "RANDOM", "Gagal membuat API key"}
	}
	clientKey, err := newClientKey()
	if err != nil {
		return ledger.App{}, "", &apiError{http.StatusInternalServerError, "RANDOM", "Gagal membuat client key"}
	}
	app := ledger.App{ID: "app_" + strings.TrimPrefix(utils.PaymentID(), "pay_"), Name: name, MerchantID: merchantID, ClientKey: clientKey}
	if err := s.Store.CreateApp(ctx, app, hashKey(key)); err != nil {
		return ledger.App{}, "", &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan aplikasi"}
	}
	return app, key, nil
}

func newAppResponse(app ledger.App, key string) map[string]any {
	return map[string]any{
		"app": map[string]any{"id": app.ID, "name": app.Name, "merchant_id": app.MerchantID, "client_key": app.ClientKey},
		// hanya ditampilkan sekali; gateway menyimpan hash-nya saja
		"api_key": key,
		// publik, boleh di browser; selalu bisa dilihat lagi
		"client_key": app.ClientKey,
	}
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

// reconcile reads the merchant feed and settles the invoice through the claim
// ledger, then queues a webhook if the invoice changed status.
func (s *Server) reconcile(ctx context.Context, inv ledger.Invoice) (ledger.Invoice, error) {
	feed, err := s.merchantFeed(ctx, inv.MerchantID, inv.CreatedAt.Add(-time.Minute))
	return s.settleWith(ctx, inv, feed, err)
}

// settleWith applies an already-fetched feed (or feed error) to one invoice and
// notifies the app when it moved from pending to paid/expired.
func (s *Server) settleWith(ctx context.Context, inv ledger.Invoice, feed []core.MerchantTransaction, feedErr error) (ledger.Invoice, error) {
	var gw *gatewayError
	if feedErr != nil && !errors.As(feedErr, &gw) {
		return inv, feedErr
	}
	now := s.Now().UTC()
	var out ledger.Invoice
	var err error
	if feedErr != nil {
		// tetap boleh kedaluwarsa walau Shopee tidak bisa dihubungi
		if !now.After(inv.ExpiresAt.Add(2 * time.Minute)) {
			return inv, feedErr
		}
		if _, err := s.Store.MarkExpired(ctx, inv.ID); err != nil {
			return inv, err
		}
		out, err = s.Store.GetInvoice(ctx, inv.AppID, inv.ID)
	} else {
		out, err = ledger.Settle(ctx, s.Store, inv, feed, now)
	}
	if err != nil {
		return inv, err
	}
	if inv.Status == ledger.StatusPending && out.Status != ledger.StatusPending {
		s.notifyTransition(ctx, out)
	}
	return out, nil
}

// merchantFeed reads the merchant's recent transactions since start (renewing
// the Shopee session if needed, under the merchant lock so concurrent polls
// never race on cookies). Feed problems come back as *gatewayError.
func (s *Server) merchantFeed(ctx context.Context, merchantID string, start time.Time) ([]core.MerchantTransaction, error) {
	now := s.Now().UTC()
	var feed []core.MerchantTransaction
	var feedErr error

	err := s.Store.WithMerchantLock(ctx, merchantID, func(m *ledger.Merchant) error {
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
		end := now.Add(time.Minute)

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
		return nil, err
	}
	if feedErr != nil {
		return nil, feedErr
	}
	return feed, nil
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
