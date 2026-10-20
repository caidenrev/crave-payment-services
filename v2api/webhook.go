package v2api

// Webhook: gateway mengabari server aplikasi saat tagihan lunas/kedaluwarsa.
//
//	POST <webhook_url>
//	Content-Type: application/json
//	X-CravePay-Event: invoice.paid | invoice.expired | ping
//	X-CravePay-Event-Id: evt_…
//	X-CravePay-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
//
//	{"id":"evt_…","type":"invoice.paid","created_at":"…","data":{"id":"inv_…","order_id":"…","amount":25000,"status":"paid",…}}
//
// Event dicoba langsung saat perubahan status terlihat, lalu diulang oleh
// POST /api/v2/internal/sweep (cron tiap menit) dengan jeda bertingkat sampai
// ±1 hari. Sweep yang sama juga mengecek tagihan pending yang tidak dicek
// siapa pun, supaya pembayaran tetap ketahuan walau popup sudah ditutup.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/utils"
)

// HTTPDoer mengirim request webhook (http.Client di produksi, palsu di tes).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

var defaultWebhookClient HTTPDoer = &http.Client{
	Timeout: 5 * time.Second,
	// jangan ikuti redirect: URL tujuan sudah divalidasi, redirect bisa mengarah ke mana saja
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

const (
	webhookSecretPrefix = "whsec_"
	maxWebhookURL       = 500
	// Event yang dicoba langsung tidak diambil sweep selama jeda ini.
	inlineLease   = 2 * time.Minute
	inlineTimeout = 4 * time.Second
	sweepLease    = 2 * time.Minute
	// Batas kerja satu sweep (fungsi Vercel bawaan ±10 dtk); sisa pekerjaan
	// dilanjutkan sweep menit berikutnya.
	sweepBudget = 6 * time.Second
	// Batas satu kiriman webhook dari sweep.
	sweepSendTimeout = 3 * time.Second
	// Tagihan yang baru dicek (popup/server) dalam jeda ini dilewati sweep.
	sweepStale        = 20 * time.Second
	sweepInvoiceLimit = 50
	sweepEventLimit   = 25
)

// Jeda sebelum percobaan ulang ke-n; setelah habis event ditandai failed.
var retryBackoff = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour,
}

func (s *Server) webhookClient() HTTPDoer {
	if s.Webhooks != nil {
		return s.Webhooks
	}
	return defaultWebhookClient
}

// validateWebhookURL hanya menerima https ke host publik (bukan localhost atau
// alamat jaringan internal), kecuali AllowInsecureWebhooks untuk tes.
func validateWebhookURL(raw string, allowInsecure bool) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(raw) > maxWebhookURL || u.User != nil {
		return "", errors.New("url webhook tidak valid (maks. 500 karakter, tanpa user:password)")
	}
	if u.Scheme != "https" && !(allowInsecure && u.Scheme == "http") {
		return "", errors.New("url webhook harus diawali https://")
	}
	if !allowInsecure {
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
			return "", errors.New("url webhook harus alamat publik")
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()) {
			return "", errors.New("url webhook harus alamat publik")
		}
	}
	return u.String(), nil
}

// signPayload membuat header X-CravePay-Signature (pola yang sama dengan Stripe).
func signPayload(secret string, t int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", t)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(mac.Sum(nil)))
}

func newEventID() string { return "evt_" + strings.TrimPrefix(utils.PaymentID(), "pay_") }

func eventBody(id, typ string, at time.Time, data map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"id": id, "type": typ, "created_at": at, "data": data})
	return b
}

func invoiceEventData(inv ledger.Invoice) map[string]any {
	data := map[string]any{
		"id": inv.ID, "order_id": inv.OrderID, "amount": inv.Amount, "status": inv.Status,
		"created_at": inv.CreatedAt, "expires_at": inv.ExpiresAt,
	}
	if inv.PaidAt != nil {
		data["paid_at"] = *inv.PaidAt
		data["transaction_id"] = inv.TransactionID
		data["payment_type"] = inv.PaymentType
	}
	return data
}

// postWebhook mengirim satu event. Hanya 2xx dianggap berhasil.
func (s *Server) postWebhook(ctx context.Context, app ledger.App, evID, evType string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CravePay-Webhooks/1")
	req.Header.Set("X-CravePay-Event", evType)
	req.Header.Set("X-CravePay-Event-Id", evID)
	req.Header.Set("X-CravePay-Signature", signPayload(app.WebhookSecret, s.Now().Unix(), body))
	resp, err := s.webhookClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// attempt mengirim ev sekali dan menyimpan hasilnya (terkirim, dijadwalkan ulang, atau gagal).
func (s *Server) attempt(ctx context.Context, app ledger.App, ev ledger.WebhookEvent, timeout time.Duration) ledger.WebhookEvent {
	now := s.Now().UTC()
	ev.Attempts++
	var err error
	if app.WebhookURL == "" || app.WebhookSecret == "" {
		err = errors.New("webhook aplikasi sudah dimatikan")
	} else {
		sendCtx, cancel := context.WithTimeout(ctx, timeout)
		_, err = s.postWebhook(sendCtx, app, ev.ID, ev.Type, ev.Payload)
		cancel()
	}
	switch {
	case err == nil:
		ev.Status, ev.LastError, ev.DeliveredAt = ledger.EventDelivered, "", &now
	case app.WebhookURL == "" || ev.Attempts > len(retryBackoff):
		ev.Status, ev.LastError = ledger.EventFailed, truncate(err.Error(), 300)
	default:
		ev.LastError = truncate(err.Error(), 300)
		ev.NextAttemptAt = now.Add(retryBackoff[ev.Attempts-1])
	}
	_ = s.Store.SaveEventAttempt(ctx, ev)
	return ev
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// notifyTransition mengantrekan invoice.paid / invoice.expired untuk aplikasi
// pemilik tagihan dan mencoba mengirimnya langsung. Panggilan ganda untuk
// perubahan yang sama aman: antrean unik per (tagihan, jenis event).
func (s *Server) notifyTransition(ctx context.Context, inv ledger.Invoice) {
	app, err := s.Store.AppByID(ctx, inv.AppID)
	if err != nil || app.WebhookURL == "" {
		return
	}
	now := s.Now().UTC()
	ev := ledger.WebhookEvent{
		ID: newEventID(), AppID: app.ID, InvoiceID: inv.ID, Type: "invoice." + inv.Status,
		Status: ledger.EventPending, NextAttemptAt: now.Add(inlineLease), CreatedAt: now,
	}
	ev.Payload = eventBody(ev.ID, ev.Type, now, invoiceEventData(inv))
	if created, err := s.Store.EnqueueEvent(ctx, ev); err != nil || !created {
		return
	}
	s.attempt(ctx, app, ev, inlineTimeout)
}

/* ---------------------------------------------------------------- sweep */

func (s *Server) isCron(r *http.Request) bool {
	tok := bearer(r)
	return s.CronSecret != "" && tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.CronSecret)) == 1
}

// sweep mengecek tagihan pending yang lama tidak dicek (satu pengambilan mutasi
// Shopee per merchant) dan mengirim ulang webhook yang jatuh tempo.
func (s *Server) sweep(w http.ResponseWriter, r *http.Request) {
	if !s.isCron(r) {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "Token cron tidak valid")
		return
	}
	ctx := r.Context()
	started := time.Now()
	overBudget := func() bool { return time.Since(started) > sweepBudget || ctx.Err() != nil }
	now := s.Now().UTC()
	sum := map[string]int{"checked": 0, "paid": 0, "expired": 0, "unavailable": 0, "delivered": 0, "retrying": 0, "failed": 0}

	invs, err := s.Store.SweepCandidates(ctx, now.Add(-sweepStale), sweepInvoiceLimit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	var order []string
	byMerchant := map[string][]ledger.Invoice{}
	for _, inv := range invs {
		if _, ok := byMerchant[inv.MerchantID]; !ok {
			order = append(order, inv.MerchantID)
		}
		byMerchant[inv.MerchantID] = append(byMerchant[inv.MerchantID], inv)
	}
	for _, merchantID := range order {
		if overBudget() {
			break
		}
		var claimed []ledger.Invoice
		earliest := now
		for _, inv := range byMerchant[merchantID] {
			// klaim dulu: popup/server yang sedang mengecek tagihan ini didahulukan
			if ok, err := s.Store.TryMarkChecked(ctx, inv.ID, now, sweepStale); err == nil && ok {
				claimed = append(claimed, inv)
				if inv.CreatedAt.Before(earliest) {
					earliest = inv.CreatedAt
				}
			}
		}
		if len(claimed) == 0 {
			continue
		}
		feed, feedErr := s.merchantFeed(ctx, merchantID, earliest.Add(-time.Minute))
		for _, inv := range claimed {
			out, err := s.settleWith(ctx, inv, feed, feedErr)
			sum["checked"]++
			switch {
			case err != nil:
				sum["unavailable"]++
			case out.Status == ledger.StatusPaid:
				sum["paid"]++
			case out.Status == ledger.StatusExpired:
				sum["expired"]++
			}
		}
	}

	if !overBudget() {
		evs, err := s.Store.LeaseDueEvents(ctx, now, sweepLease, sweepEventLimit)
		if err == nil {
			for _, ev := range evs {
				if overBudget() {
					break // sisanya diambil lagi setelah lease habis
				}
				app, err := s.Store.AppByID(ctx, ev.AppID)
				if err != nil {
					app = ledger.App{ID: ev.AppID}
				}
				res := s.attempt(ctx, app, ev, sweepSendTimeout)
				switch res.Status {
				case ledger.EventDelivered:
					sum["delivered"]++
				case ledger.EventFailed:
					sum["failed"]++
				default:
					sum["retrying"]++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "summary": sum, "took_ms": time.Since(started).Milliseconds()})
}

/* ---------------------------------------------------------------- admin */

func (s *Server) appOr404(w http.ResponseWriter, r *http.Request, id string) (ledger.App, bool) {
	app, err := s.Store.AppByID(r.Context(), id)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Aplikasi tidak ditemukan")
		return app, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return app, false
	}
	return app, true
}

// putWebhook mengatur URL webhook. Secret dibuat sekali (lalu dipakai ulang);
// url "" mematikan webhook tanpa membuang secret.
func (s *Server) putWebhook(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.appOr404(w, r, appID)
	if !ok {
		return
	}
	s.writeWebhookUpdate(w, r, app)
}

// writeWebhookUpdate membaca {url} dan mengatur webhook aplikasi (dipakai admin & console).
func (s *Server) writeWebhookUpdate(w http.ResponseWriter, r *http.Request, app ledger.App) {
	var req struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &req) {
		return
	}
	target := ""
	if strings.TrimSpace(req.URL) != "" {
		var err error
		if target, err = validateWebhookURL(req.URL, s.AllowInsecureWebhooks); err != nil {
			writeErr(w, http.StatusBadRequest, "INVALID_WEBHOOK_URL", err.Error())
			return
		}
	}
	secret := app.WebhookSecret
	if secret == "" {
		var err error
		if secret, err = randomKey(webhookSecretPrefix, 24); err != nil {
			writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat secret webhook")
			return
		}
	}
	if err := s.Store.SetWebhook(r.Context(), app.ID, target, secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan webhook")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": app.ID, "webhook_url": target, "webhook_secret": secret})
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.appOr404(w, r, appID)
	if !ok {
		return
	}
	secret, err := randomKey(webhookSecretPrefix, 24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat secret webhook")
		return
	}
	if err := s.Store.SetWebhook(r.Context(), app.ID, app.WebhookURL, secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan webhook")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": app.ID, "webhook_secret": secret})
}

// testWebhook mengirim event "ping" sekarang juga dan melaporkan hasilnya.
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.appOr404(w, r, appID)
	if !ok {
		return
	}
	if app.WebhookURL == "" {
		writeErr(w, http.StatusBadRequest, "WEBHOOK_NOT_SET", "URL webhook belum diatur")
		return
	}
	id := newEventID()
	body := eventBody(id, "ping", s.Now().UTC(), map[string]any{"app_id": app.ID})
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	code, err := s.postWebhook(ctx, app, id, "ping", body)
	out := map[string]any{"success": err == nil, "event_id": id, "status_code": code}
	if err != nil {
		out["error"] = truncate(err.Error(), 300)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listWebhookEvents(w http.ResponseWriter, r *http.Request, appID string) {
	if _, ok := s.appOr404(w, r, appID); !ok {
		return
	}
	evs, err := s.Store.ListEvents(r.Context(), appID, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca event")
		return
	}
	out := make([]map[string]any, 0, len(evs))
	for _, ev := range evs {
		item := map[string]any{
			"id": ev.ID, "type": ev.Type, "invoice_id": ev.InvoiceID, "status": ev.Status,
			"attempts": ev.Attempts, "last_error": ev.LastError, "created_at": ev.CreatedAt,
		}
		if ev.Status == ledger.EventPending {
			item["next_attempt_at"] = ev.NextAttemptAt
		}
		if ev.DeliveredAt != nil {
			item["delivered_at"] = *ev.DeliveredAt
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
