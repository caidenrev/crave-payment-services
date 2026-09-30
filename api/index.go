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

	path := strings.ToLower(r.URL.Path)
	if matched := r.Header.Get("x-matched-path"); matched != "" {
		path = strings.ToLower(matched)
	}

	// Create payment endpoint (POST)
	if strings.Contains(path, "payment") && r.Method == http.MethodPost {
		handleCreatePayment(w, r)
		return
	}

	// Get payment status endpoint (GET)
	if strings.Contains(path, "payment") && r.Method == http.MethodGet {
		handleGetPayment(w, r)
		return
	}

	// Health check endpoint (Default for /, /health, /api/health, /api/index)
	handleHealth(w, r)
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

	now := time.Now()
	if req.OrderID == "" {
		req.OrderID = fmt.Sprintf("ORD-%d", now.Unix())
	}

	expiryMinutes := 10
	if req.ExpiresInMinutes > 0 && req.ExpiresInMinutes <= 60 {
		expiryMinutes = req.ExpiresInMinutes
	}
	expiresAt := now.Add(time.Duration(expiryMinutes) * time.Minute)

	p, service, err := getProvider()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	staticQris := os.Getenv("STATIC_QRIS")
	if staticQris == "" {
		staticQris = "00020101021126610016ID.CO.SHOPEE.WWW01189360091800237970570208237970570303UMI51440014ID.CO.QRIS.WWW0215ID10266049176290303UMI5204572253033605802ID5923Crave Solutions Service6007TANGSEL61051531262070703A016304351F"
	}

	dynamicQR, err := qris.StaticToDynamicQris(staticQris, req.Amount)
	if err != nil {
		// Fallback to service if helper error
		if service != nil {
			pay, errSvc := service.CreatePayment(r.Context(), payment.CreatePaymentInput{
				Amount:    req.Amount,
				Reference: req.OrderID,
				ExpiresIn: time.Duration(expiryMinutes) * time.Minute,
			})
			if errSvc == nil {
				dynamicQR = pay.QRString
			}
		}
	}

	qrB64 := ""
	if dynamicQR != "" {
		code, err := qr.Encode(dynamicQR, qr.M)
		if err == nil {
			qrB64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
		}
	}

	// Stateless self-describing payment ID: pay_<amount>_<unix>_<nonce>
	randSuffix := fmt.Sprintf("%x", time.Now().UnixNano()%1000000)
	paymentID := fmt.Sprintf("pay_%d_%d_%s", req.Amount, now.Unix(), randSuffix)

	_ = p // provider active

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
	p, _, err := getProvider()
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

	if id == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]any{"error": "payment_id required"})
		return
	}

	// Parse target amount and creation time from self-describing payment ID or query params
	var targetAmount int64
	createdAt := time.Now().Add(-10 * time.Minute)

	if qAmount := r.URL.Query().Get("amount"); qAmount != "" {
		if a, err := strconv.ParseInt(qAmount, 10, 64); err == nil {
			targetAmount = a
		}
	}

	parts := strings.Split(id, "_")
	if len(parts) >= 3 && parts[0] == "pay" {
		if a, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			targetAmount = a
		}
		if u, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
			createdAt = time.Unix(u, 0)
		}
	}

	// Query real-time Shopee transaction feed around the payment creation window
	searchStart := createdAt.Add(-3 * time.Minute)
	searchEnd := time.Now().Add(3 * time.Minute)

	txs, err := p.GetRecentTransactions(r.Context(), searchStart, searchEnd)
	if err == nil {
		for _, tx := range txs {
			// Check if matching amount and transaction occurred around/after payment creation
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

	// If no completed transaction found yet, check expiry (10 min)
	if time.Now().After(createdAt.Add(12 * time.Minute)) {
		jsonResponse(w, http.StatusOK, map[string]any{
			"success":       true,
			"payment_id":    id,
			"unique_amount": targetAmount,
			"status":        "EXPIRED",
		})
		return
	}

	// Still waiting for payment
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
