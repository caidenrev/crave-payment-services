package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hirotomasato/paygateme/payment"
	"github.com/hirotomasato/paygateme/qris"
	"github.com/hirotomasato/paygateme/shopee"
	"github.com/hirotomasato/paygateme/utils"
	"rsc.io/qr"
)

var (
	defaultProvider *shopee.Provider
	defaultSvc      *payment.Service
	defaultSession  shopee.Session
	mu              sync.Mutex
)

func getDefaultProvider() (*shopee.Provider, *payment.Service, error) {
	mu.Lock()
	defer mu.Unlock()

	if defaultSvc != nil && defaultProvider != nil {
		return defaultProvider, defaultSvc, nil
	}

	staticQris := os.Getenv("STATIC_QRIS")

	var data []byte
	var err error
	if envSession := os.Getenv("SESSION_JSON"); envSession != "" {
		data = []byte(envSession)
	} else {
		data, err = os.ReadFile("session.json")
		if err != nil {
			return nil, nil, fmt.Errorf("session.json / SESSION_JSON not found: %w", err)
		}
	}

	if err := json.Unmarshal(data, &defaultSession); err != nil {
		return nil, nil, fmt.Errorf("error decoding session JSON: %w", err)
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	allocator := payment.NewExactAmountAllocator(true)

	defaultProvider = shopee.NewProvider(shopee.ProviderConfig{
		Session:      &defaultSession,
		StaticQris:   staticQris,
		Allocator:    allocator,
		PollInterval: 5000,
		ClockSkew:    300000, // 5 min tolerance
		Logger:       logger,
	})

	ctx := context.Background()
	_, _ = defaultProvider.RefreshSession(ctx)

	s, err := defaultProvider.Payments()
	if err != nil {
		return nil, nil, fmt.Errorf("provider.Payments error: %w", err)
	}
	defaultSvc = s

	return defaultProvider, defaultSvc, nil
}

// Handler is the Vercel Go Serverless entrypoint
func Handler(w http.ResponseWriter, r *http.Request) {
	// CORS Headers for any SaaS domain
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Shopee-Session, X-Static-Qris")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := strings.ToLower(r.URL.Path)
	if matched := r.Header.Get("x-matched-path"); matched != "" {
		path = strings.ToLower(matched)
	}

	// 1. Auth OTP Request
	if strings.Contains(path, "otp/request") || strings.Contains(path, "auth/request-otp") {
		handleRequestOtp(w, r)
		return
	}

	// 2. Auth OTP Verify
	if strings.Contains(path, "otp/verify") || strings.Contains(path, "auth/verify-otp") {
		handleVerifyOtp(w, r)
		return
	}

	// 3. Auth Complete Login
	if strings.Contains(path, "auth/complete") || strings.Contains(path, "auth/complete-login") {
		handleCompleteLogin(w, r)
		return
	}

	// 4. Merchant Check / Info
	if strings.Contains(path, "merchant/check") || strings.Contains(path, "merchant/info") {
		handleMerchantCheck(w, r)
		return
	}

	// 5. Payment Status Check via POST /status or /payment/status
	if strings.Contains(path, "payment/status") || strings.Contains(path, "status") && r.Method == http.MethodPost {
		handleGetPayment(w, r)
		return
	}

	// 6. Create payment endpoint (POST)
	if strings.Contains(path, "payment") && r.Method == http.MethodPost {
		handleCreatePayment(w, r)
		return
	}

	// 7. Get payment status endpoint (GET)
	if strings.Contains(path, "payment") && r.Method == http.MethodGet {
		handleGetPayment(w, r)
		return
	}

	// Health check endpoint (Default for /, /health, /api/health, /api/index)
	handleHealth(w, r)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	p, _, err := getDefaultProvider()
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]any{
			"status": "warning",
			"error":  err.Error(),
		})
		return
	}

	s := p.ExportSession()
	merchantName := "Multi-Tenant Payment Gateway"
	storeID := "-"
	if s != nil {
		if s.Merchant.Name != "" {
			merchantName = s.Merchant.Name
		}
		if s.StoreID != "" {
			storeID = s.StoreID
		}
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"merchant":  merchantName,
		"store_id":  storeID,
		"timestamp": time.Now().Unix(),
		"runtime":   "Vercel Serverless (Go Multi-Tenant)",
	})
}

func handleRequestOtp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]any{"error": "Method not allowed"})
		return
	}

	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body"})
		return
	}

	if strings.TrimSpace(req.Phone) == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Nomor telepon Shopee wajib diisi"})
		return
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	httpClient := shopee.NewHTTPClient(logger)
	authClient := shopee.NewAuthClient(httpClient, shopee.APILocale{}, logger)

	challenge, err := authClient.RequestOtp(r.Context(), req.Phone, shopee.OtpRequestOptions{
		Password:     req.Password,
		DeviceReport: shopee.DeviceRiskBlob,
	})
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	channelName := "WhatsApp"
	switch challenge.Channel {
	case 1:
		channelName = "SMS"
	case 2:
		channelName = "Panggilan Suara"
	case 3:
		channelName = "WhatsApp"
	case 5:
		channelName = "Notifikasi Aplikasi Shopee"
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":      true,
		"challenge":    challenge,
		"channel_name": channelName,
		"message":      fmt.Sprintf("Kode OTP telah dikirim via %s ke %s", channelName, challenge.PhoneNumber),
	})
}

func handleVerifyOtp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]any{"error": "Method not allowed"})
		return
	}

	var req struct {
		Challenge  shopee.OtpChallenge `json:"challenge"`
		OTP        string              `json:"otp"`
		MerchantID string              `json:"merchant_id"`
		StoreID    string              `json:"store_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body: " + err.Error()})
		return
	}

	if strings.TrimSpace(req.OTP) == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Kode OTP wajib diisi"})
		return
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	provider := shopee.NewProvider(shopee.ProviderConfig{
		DeviceReport: shopee.DeviceRiskBlob,
		Logger:       logger,
	})

	outcome, err := provider.LoginWithOtp(r.Context(), shopee.LoginWithOtpInput{
		Challenge:  req.Challenge,
		OTP:        req.OTP,
		MerchantID: req.MerchantID,
		StoreID:    req.StoreID,
	})
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	if outcome.Status == shopee.LoginMerchantSelectionNeeded {
		jsonResponse(w, http.StatusOK, map[string]any{
			"success":      true,
			"status":       "MERCHANT_SELECTION_NEEDED",
			"merchants":    outcome.Merchants,
			"verification": outcome.Verification,
		})
		return
	}

	session := outcome.Session
	if session == nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": "Login berhasil tetapi sesi tidak terbentuk"})
		return
	}

	// Try auto-selecting store if only 1 store
	stores, _ := provider.ListStores(r.Context())
	if len(stores) > 0 && session.StoreID == "" {
		_, _ = provider.SelectStore(r.Context(), stores[0].ID)
		session = provider.ExportSession()
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":  true,
		"status":   "CONNECTED",
		"session":  session,
		"merchant": session.Merchant,
		"store_id": session.StoreID,
		"stores":   stores,
	})
}

func handleCompleteLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]any{"error": "Method not allowed"})
		return
	}

	var req struct {
		Verification shopee.OtpVerification `json:"verification"`
		MerchantID   string                 `json:"merchant_id"`
		StoreID      string                 `json:"store_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body"})
		return
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	provider := shopee.NewProvider(shopee.ProviderConfig{
		DeviceReport: shopee.DeviceRiskBlob,
		Logger:       logger,
	})

	session, err := provider.CompleteLogin(r.Context(), shopee.CompleteLoginInput{
		Verification: req.Verification,
		MerchantID:   req.MerchantID,
		StoreID:      req.StoreID,
	})
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	stores, _ := provider.ListStores(r.Context())
	if len(stores) > 0 && session.StoreID == "" {
		_, _ = provider.SelectStore(r.Context(), stores[0].ID)
		session = provider.ExportSession()
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":  true,
		"status":   "CONNECTED",
		"session":  session,
		"merchant": session.Merchant,
		"store_id": session.StoreID,
		"stores":   stores,
	})
}

func handleMerchantCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]any{"error": "Method not allowed"})
		return
	}

	var req struct {
		SessionJSON string          `json:"session_json"`
		Session     *shopee.Session `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid request body"})
		return
	}

	var sess shopee.Session
	if req.Session != nil {
		sess = *req.Session
	} else if strings.TrimSpace(req.SessionJSON) != "" {
		if err := json.Unmarshal([]byte(req.SessionJSON), &sess); err != nil {
			jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Format Session JSON tidak valid: " + err.Error()})
			return
		}
	} else {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Session JSON diperlukan"})
		return
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	provider := shopee.NewProvider(shopee.ProviderConfig{
		Session:      &sess,
		DeviceReport: shopee.DeviceRiskBlob,
		Logger:       logger,
	})

	_, err := provider.RefreshSession(r.Context())
	activeSession := provider.ExportSession()
	if activeSession == nil {
		jsonResponse(w, http.StatusOK, map[string]any{
			"success": false,
			"active":  false,
			"error":   "Sesi Shopee kedaluwarsa atau tidak valid",
		})
		return
	}

	stores, _ := provider.ListStores(r.Context())

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":  true,
		"active":   true,
		"session":  activeSession,
		"merchant": activeSession.Merchant,
		"store_id": activeSession.StoreID,
		"stores":   stores,
		"err":      err,
	})
}

func handleCreatePayment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrderID          string          `json:"order_id"`
		Amount           int64           `json:"amount"`
		ExpiresInMinutes int             `json:"expires_in_minutes"`
		StaticQRIS       string          `json:"static_qris"`
		SessionJSON      string          `json:"session_json"`
		Session          *shopee.Session `json:"session"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON body"})
		return
	}

	if req.Amount <= 0 {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Amount must be greater than 0"})
		return
	}

	now := time.Now()
	if req.OrderID == "" {
		req.OrderID = fmt.Sprintf("ORD-%d", now.Unix())
	}

	expiryMinutes := 10
	if req.ExpiresInMinutes > 0 && req.ExpiresInMinutes <= 60 {
		expiryMinutes = req.ExpiresInMinutes
	}
	expiresAt := now.Add(time.Duration(expiryMinutes) * time.Minute)

	// Determine static QRIS
	staticQris := strings.TrimSpace(req.StaticQRIS)
	if staticQris == "" {
		staticQris = strings.TrimSpace(r.Header.Get("X-Static-Qris"))
	}
	if staticQris == "" {
		staticQris = strings.TrimSpace(os.Getenv("STATIC_QRIS"))
	}
	if staticQris == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{
			"error": "QRIS Statis belum dikonfigurasi. Silakan atur String QRIS Statis toko Anda di menu Pengaturan > QRIS Merchant.",
		})
		return
	}

	dynamicQR, err := qris.StaticToDynamicQris(staticQris, req.Amount)
	if err != nil {
		p, service, errDef := getDefaultProvider()
		if errDef == nil && service != nil {
			pay, errSvc := service.CreatePayment(r.Context(), payment.CreatePaymentInput{
				Amount:    req.Amount,
				Reference: req.OrderID,
				ExpiresIn: time.Duration(expiryMinutes) * time.Minute,
			})
			if errSvc == nil {
				dynamicQR = pay.QRString
			}
		}
		_ = p
	}

	qrB64 := ""
	if dynamicQR != "" {
		code, err := qr.Encode(dynamicQR, qr.M)
		if err == nil {
			qrB64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
		}
	}

	randSuffix := fmt.Sprintf("%x", time.Now().UnixNano()%1000000)
	paymentID := fmt.Sprintf("pay_%d_%d_%s", req.Amount, now.Unix(), randSuffix)

	jsonResponse(w, http.StatusCreated, map[string]any{
		"success":           true,
		"payment_id":        paymentID,
		"order_id":          req.OrderID,
		"amount":            req.Amount,
		"unique_amount":     req.Amount,
		"unique_offset":     0,
		"status":            "pending",
		"qris_string":       dynamicQR,
		"qris_image_base64": qrB64,
		"expires_at":        expiresAt,
		"created_at":        now,
	})
}

func handleGetPayment(w http.ResponseWriter, r *http.Request) {
	// Parse target amount and creation time
	var targetAmount int64
	var id string
	var userSession *shopee.Session

	// Check if POST with JSON body
	if r.Method == http.MethodPost {
		var postReq struct {
			PaymentID   string          `json:"payment_id"`
			Amount      int64           `json:"amount"`
			SessionJSON string          `json:"session_json"`
			Session     *shopee.Session `json:"session"`
		}
		if err := json.NewDecoder(r.Body).Decode(&postReq); err == nil {
			id = postReq.PaymentID
			targetAmount = postReq.Amount
			if postReq.Session != nil {
				userSession = postReq.Session
			} else if postReq.SessionJSON != "" {
				var s shopee.Session
				if err := json.Unmarshal([]byte(postReq.SessionJSON), &s); err == nil {
					userSession = &s
				}
			}
		}
	}

	// Fallback / standard extraction
	if id == "" {
		id = strings.TrimPrefix(r.URL.Path, "/api/payments/")
		id = strings.TrimPrefix(id, "/api/payments")
		id = strings.TrimPrefix(id, "/payments/")
		id = strings.TrimPrefix(id, "/api/payment/status")
		id = strings.TrimPrefix(id, "/payment/status")
		id = strings.TrimPrefix(id, "/")
		if id == "" {
			id = r.URL.Query().Get("id")
		}
		if id == "" {
			id = r.URL.Query().Get("payment_id")
		}
	}

	if id == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "payment_id required"})
		return
	}

	if targetAmount == 0 {
		if qAmount := r.URL.Query().Get("amount"); qAmount != "" {
			if a, err := strconv.ParseInt(qAmount, 10, 64); err == nil {
				targetAmount = a
			}
		}
	}

	// Check header for dynamic session
	if userSession == nil {
		if headerSession := r.Header.Get("X-Shopee-Session"); headerSession != "" {
			var s shopee.Session
			if err := json.Unmarshal([]byte(headerSession), &s); err == nil {
				userSession = &s
			}
		}
	}

	createdAt := time.Now().Add(-10 * time.Minute)
	parts := strings.Split(id, "_")
	if len(parts) >= 3 && parts[0] == "pay" {
		if targetAmount == 0 {
			if a, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				targetAmount = a
			}
		}
		if u, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
			createdAt = time.Unix(u, 0)
		}
	}

	// Instantiate the provider (either user dynamic provider or default)
	var activeProvider *shopee.Provider
	if userSession != nil {
		logger := utils.NewConsoleLogger(utils.LevelInfo)
		activeProvider = shopee.NewProvider(shopee.ProviderConfig{
			Session: userSession,
			Logger:  logger,
		})
	} else {
		p, _, err := getDefaultProvider()
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		activeProvider = p
	}

	searchStart := createdAt.Add(-3 * time.Minute)
	searchEnd := time.Now().Add(3 * time.Minute)

	txs, err := activeProvider.GetRecentTransactions(r.Context(), searchStart, searchEnd)
	if err == nil {
		for _, tx := range txs {
			amountMatches := (targetAmount == 0 || tx.Amount == targetAmount)
			timeMatches := tx.Time.After(createdAt.Add(-60 * time.Second))

			if amountMatches && timeMatches {
				jsonResponse(w, http.StatusOK, map[string]any{
					"success":        true,
					"payment_id":     id,
					"order_id":       tx.OrderID,
					"amount":         tx.Amount,
					"unique_amount":  tx.Amount,
					"status":         "PAID",
					"paid_at":        tx.Time,
					"transaction_id": tx.ID,
					"payment_type":   tx.PaymentType,
				})
				return
			}
		}
	}

	if time.Now().After(createdAt.Add(12 * time.Minute)) {
		jsonResponse(w, http.StatusOK, map[string]any{
			"success":       true,
			"payment_id":    id,
			"unique_amount": targetAmount,
			"status":        "EXPIRED",
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"success":       true,
		"payment_id":    id,
		"unique_amount": targetAmount,
		"status":        "PENDING",
	})
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
