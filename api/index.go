package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirotomasato/paygateme/payment"
	"github.com/hirotomasato/paygateme/shopee"
	"github.com/hirotomasato/paygateme/utils"
	"rsc.io/qr"
)

var (
	provider *shopee.Provider
	svc      *payment.Service
	session  shopee.Session
	mu       sync.Mutex
)

func getProvider() (*shopee.Provider, *payment.Service, error) {
	mu.Lock()
	defer mu.Unlock()

	if svc != nil && provider != nil {
		return provider, svc, nil
	}

	staticQris := os.Getenv("STATIC_QRIS")
	if staticQris == "" {
		staticQris = "00020101021126610016ID.CO.SHOPEE.WWW01189360091800237970570208237970570303UMI51440014ID.CO.QRIS.WWW0215ID10266049176290303UMI5204572253033605802ID5923Crave Solutions Service6007TANGSEL61051531262070703A016304351F"
	}

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

	if err := json.Unmarshal(data, &session); err != nil {
		return nil, nil, fmt.Errorf("error decoding session JSON: %w", err)
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	allocator := payment.NewExactAmountAllocator(true)

	provider = shopee.NewProvider(shopee.ProviderConfig{
		Session:      &session,
		StaticQris:   staticQris,
		Allocator:    allocator,
		PollInterval: 5000,
		ClockSkew:    300000, // 5 min tolerance
		Logger:       logger,
	})

	ctx := context.Background()
	_, _ = provider.RefreshSession(ctx)

	s, err := provider.Payments()
	if err != nil {
		return nil, nil, fmt.Errorf("provider.Payments error: %w", err)
	}
	svc = s

	return provider, svc, nil
}

// Handler is the Vercel Go Serverless entrypoint
func Handler(w http.ResponseWriter, r *http.Request) {
	// CORS Headers for any SaaS domain
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path

	// Health check endpoint
	if path == "/health" || path == "/api/health" || path == "/" {
		handleHealth(w, r)
		return
	}

	// Create payment endpoint
	if (path == "/api/payments" || path == "/payments") && r.Method == http.MethodPost {
		handleCreatePayment(w, r)
		return
	}

	// Get payment status endpoint
	if strings.HasPrefix(path, "/api/payments") || strings.HasPrefix(path, "/payments") {
		handleGetPayment(w, r)
		return
	}

	http.NotFound(w, r)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	p, _, err := getProvider()
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]any{
			"status": "warning",
			"error":  err.Error(),
		})
		return
	}

	s := p.ExportSession()
	merchantName := "Crave Solutions Service"
	storeID := "23797057"
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
		"runtime":   "Vercel Serverless (Go)",
	})
}

func handleCreatePayment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrderID          string `json:"order_id"`
		Amount           int64  `json:"amount"`
		ExpiresInMinutes int    `json:"expires_in_minutes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON body"})
		return
	}

	if req.Amount <= 0 {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "Amount must be greater than 0"})
		return
	}

	if req.OrderID == "" {
		req.OrderID = fmt.Sprintf("ORD-%d", time.Now().Unix())
	}

	_, service, err := getProvider()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	expiry := 10 * time.Minute
	if req.ExpiresInMinutes > 0 && req.ExpiresInMinutes <= 60 {
		expiry = time.Duration(req.ExpiresInMinutes) * time.Minute
	}

	pay, err := service.CreatePayment(r.Context(), payment.CreatePaymentInput{
		Amount:    req.Amount,
		Reference: req.OrderID,
		ExpiresIn: expiry,
		Metadata:  map[string]any{"order_id": req.OrderID},
	})
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	qrB64 := ""
	if pay.QRString != "" {
		code, err := qr.Encode(pay.QRString, qr.M)
		if err == nil {
			qrB64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
		}
	}

	jsonResponse(w, http.StatusCreated, map[string]any{
		"success":           true,
		"payment_id":        pay.ID,
		"order_id":          pay.Reference,
		"amount":            pay.BaseAmount,
		"unique_amount":     pay.UniqueAmount,
		"unique_offset":     pay.UniqueOffset,
		"status":            string(pay.Status),
		"qris_string":       pay.QRString,
		"qris_image_base64": qrB64,
		"expires_at":        pay.ExpiresAt,
		"created_at":        pay.CreatedAt,
	})
}

func handleGetPayment(w http.ResponseWriter, r *http.Request) {
	_, service, err := getProvider()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Extract ID from URL path or query parameter
	id := strings.TrimPrefix(r.URL.Path, "/api/payments/")
	id = strings.TrimPrefix(id, "/api/payments")
	id = strings.TrimPrefix(id, "/payments/")
	id = strings.TrimPrefix(id, "/")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	// Trigger on-demand reconciliation against Shopee API
	_, _ = service.Tick(r.Context())

	if id == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "payment_id required"})
		return
	}

	pay, err := service.GetPayment(r.Context(), id)
	if err != nil || pay == nil {
		// If not in in-memory map, check active list or query Shopee
		jsonResponse(w, http.StatusOK, map[string]any{
			"success":    true,
			"payment_id": id,
			"status":     "pending",
		})
		return
	}

	res := map[string]any{
		"success":       true,
		"payment_id":    pay.ID,
		"order_id":      pay.Reference,
		"unique_amount": pay.UniqueAmount,
		"status":        string(pay.Status),
		"expires_at":    pay.ExpiresAt,
	}

	if pay.Transaction != nil {
		res["paid_at"] = pay.Transaction.Time
		res["transaction_id"] = pay.Transaction.ID
		res["payment_type"] = pay.Transaction.PaymentType
	}

	jsonResponse(w, http.StatusOK, res)
}

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
