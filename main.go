package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hirotomasato/paygateme/core"
	"github.com/hirotomasato/paygateme/payment"
	"github.com/hirotomasato/paygateme/shopee"
	"github.com/hirotomasato/paygateme/utils"
	"rsc.io/qr"
)

type Server struct {
	svc         *payment.Service
	provider    *shopee.Provider
	session     *shopee.Session
	sessionPath string
	logger      utils.Logger
	port        int
	mu          sync.RWMutex
	callbacks   map[string]string
}

type CreatePaymentRequest struct {
	OrderID          string `json:"order_id"`
	Amount           int64  `json:"amount"`
	ExpiresInMinutes int    `json:"expires_in_minutes,omitempty"`
	CallbackURL      string `json:"callback_url,omitempty"`
}

type CreatePaymentResponse struct {
	Success      bool      `json:"success"`
	PaymentID    string    `json:"payment_id"`
	OrderID      string    `json:"order_id"`
	BaseAmount   int64     `json:"amount"`
	UniqueAmount int64     `json:"unique_amount"`
	UniqueOffset int64     `json:"unique_offset"`
	Status       string    `json:"status"`
	QRISString   string    `json:"qris_string"`
	QRISImageB64 string    `json:"qris_image_base64,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type PaymentStatusResponse struct {
	Success      bool       `json:"success"`
	PaymentID    string     `json:"payment_id"`
	OrderID      string     `json:"order_id"`
	UniqueAmount int64      `json:"unique_amount"`
	Status       string     `json:"status"`
	ExpiresAt    time.Time  `json:"expires_at"`
	PaidAt       *time.Time `json:"paid_at,omitempty"`
	TxID         string     `json:"transaction_id,omitempty"`
	PaymentType  string     `json:"payment_type,omitempty"`
}

func main() {
	portVal := 8080
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			portVal = p
		}
	}
	port := flag.Int("port", portVal, "server listen port")
	sessionPath := flag.String("session", "session.json", "path to saved session JSON")
	staticQris := flag.String("qris", os.Getenv("STATIC_QRIS"), "static QRIS payload (or set STATIC_QRIS env var)")
	flag.Parse()

	if *staticQris == "" {
		fmt.Fprintln(os.Stderr, "Error: QRIS statis diperlukan via STATIC_QRIS env var.")
		os.Exit(1)
	}

	var data []byte
	var err error
	if envSession := os.Getenv("SESSION_JSON"); envSession != "" {
		data = []byte(envSession)
	} else {
		data, err = os.ReadFile(*sessionPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s tidak ditemukan: %v\n", *sessionPath, err)
			os.Exit(1)
		}
	}

	var session shopee.Session
	if err := json.Unmarshal(data, &session); err != nil {
		fmt.Fprintf(os.Stderr, "Error membaca JSON: %v\n", err)
		os.Exit(1)
	}

	logger := utils.NewConsoleLogger(utils.LevelInfo)
	allocator := payment.NewExactAmountAllocator(true)

	provider := shopee.NewProvider(shopee.ProviderConfig{
		Session:      &session,
		StaticQris:   *staticQris,
		Allocator:    allocator,
		PollInterval: 5000,
		ClockSkew:    30000,
		Logger:       logger,
		OnSessionUpdated: func(s shopee.Session) error {
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := provider.RefreshSession(ctx); err != nil {
		logger.Warn(fmt.Sprintf("Session refresh warning: %v", err), nil)
	}

	svc, err := provider.Payments()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gagal membuat payment service: %v\n", err)
		os.Exit(1)
	}

	srv := &Server{
		svc:         svc,
		provider:    provider,
		session:     &session,
		sessionPath: *sessionPath,
		logger:      logger,
		port:        *port,
		callbacks:   make(map[string]string),
	}

	svc.OnPaid(srv.handlePaymentPaid)
	svc.Start()
	defer svc.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /api/payments", srv.handleCreatePayment)
	mux.HandleFunc("GET /api/payments/", srv.handleGetPayment)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      corsMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		logger.Info(fmt.Sprintf("🚀 Server berjalan di port :%d", *port), nil)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(fmt.Sprintf("HTTP server error: %v", err), nil)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"provider":    "shopee_partner",
		"merchant":    s.session.Merchant.Name,
		"store_id":    s.session.StoreID,
		"active_slot": 0,
		"timestamp":   time.Now().Unix(),
	})
}

func (s *Server) handleCreatePayment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req CreatePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Invalid request payload"})
		return
	}

	if req.Amount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Amount harus lebih dari 0"})
		return
	}

	opts := payment.CreatePaymentOptions{
		Reference: req.OrderID,
	}
	if req.ExpiresInMinutes > 0 {
		opts.Timeout = time.Duration(req.ExpiresInMinutes) * time.Minute
	}

	p, err := s.svc.Create(r.Context(), req.Amount, opts)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}

	if req.CallbackURL != "" {
		s.mu.Lock()
		s.callbacks[p.ID] = req.CallbackURL
		s.mu.Unlock()
	}

	var qrB64 string
	if code, err := qr.Encode(p.QRIS, qr.M); err == nil {
		qrB64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}

	resp := CreatePaymentResponse{
		Success:      true,
		PaymentID:    p.ID,
		OrderID:      p.Reference,
		BaseAmount:   p.BaseAmount,
		UniqueAmount: p.UniqueAmount,
		UniqueOffset: p.UniqueAmount - p.BaseAmount,
		Status:       string(p.Status),
		QRISString:   p.QRIS,
		QRISImageB64: qrB64,
		ExpiresAt:    p.ExpiresAt,
		CreatedAt:    p.CreatedAt,
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleGetPayment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/api/payments/")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Payment ID required"})
		return
	}

	p, err := s.svc.Get(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "Payment tidak ditemukan"})
		return
	}

	resp := PaymentStatusResponse{
		Success:      true,
		PaymentID:    p.ID,
		OrderID:      p.Reference,
		UniqueAmount: p.UniqueAmount,
		Status:       string(p.Status),
		ExpiresAt:    p.ExpiresAt,
		PaidAt:       p.PaidAt,
		TxID:         p.TransactionID,
		PaymentType:  p.PaymentType,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePaymentPaid(p core.Payment) {
	s.logger.Info(fmt.Sprintf("Payment %s (Order: %s) LUNAS! Rp %d", p.ID, p.Reference, p.UniqueAmount), nil)
	s.mu.RLock()
	cbURL, exists := s.callbacks[p.ID]
	s.mu.RUnlock()

	if !exists || cbURL == "" {
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"event":          "payment.paid",
		"payment_id":     p.ID,
		"order_id":       p.Reference,
		"amount":         p.UniqueAmount,
		"transaction_id": p.TransactionID,
		"paid_at":        p.PaidAt,
	})

	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		for i := 0; i < 3; i++ {
			resp, err := client.Post(cbURL, "application/json", bytes.NewReader(payload))
			if err == nil && resp.StatusCode < 400 {
				resp.Body.Close()
				return
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(time.Duration(i+1) * 2 * time.Second)
		}
	}()
}
