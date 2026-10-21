package v2api

// Mode test (sandbox). Aplikasi test punya key berawalan pgk_test_ /
// pgk_pub_test_. Tagihannya:
//   - tidak pernah mengecek Shopee dan tidak butuh merchant terhubung/QRIS statis;
//   - memakai QR palsu yang tidak bisa dibayar (aman discan);
//   - lunas/kedaluwarsa hanya lewat simulasi, dan tetap memicu webhook seperti live.
//
//	POST /api/v2/invoices/{id}/simulate   {status: "paid" | "expired"}   (secret key test)

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hirotomasato/paygateme/ledger"
)

const (
	testSecretPrefix = "pgk_test_"
	testClientPrefix = "pgk_pub_test_"
	// Tipe pembayaran tagihan yang dilunasi lewat simulasi.
	simulatedPaymentType = "SIMULATED"
)

func newSecretKeyFor(mode string) (string, error) {
	if mode == ledger.ModeTest {
		return randomKey(testSecretPrefix, 32)
	}
	return newSecretKey()
}

func newClientKeyFor(mode string) (string, error) {
	if mode == ledger.ModeTest {
		return randomKey(testClientPrefix, 16)
	}
	return newClientKey()
}

// testQR adalah isi QR tagihan test: teks biasa, bukan QRIS, jadi aplikasi
// pembayaran mana pun menolaknya dan tidak ada uang yang berpindah.
func testQR(invoiceID string, amount int64) string {
	return fmt.Sprintf("CRAVEPAY-TEST|%s|%d|TIDAK-BISA-DIBAYAR", invoiceID, amount)
}

// settleTest hanya mengurus kedaluwarsa tagihan test (tanpa Shopee).
func (s *Server) settleTest(ctx context.Context, inv ledger.Invoice) (ledger.Invoice, error) {
	if inv.Status != ledger.StatusPending || !s.Now().UTC().After(inv.ExpiresAt) {
		return inv, nil
	}
	if _, err := s.Store.MarkExpired(ctx, inv.ID); err != nil {
		return inv, err
	}
	out, err := s.Store.GetInvoice(ctx, inv.AppID, inv.ID)
	if err != nil {
		return inv, err
	}
	if out.Status != ledger.StatusPending {
		s.notifyTransition(ctx, out)
	}
	return out, nil
}

// simulate melunasi / mengedaluwarsakan tagihan test, lalu mengirim webhook.
func (s *Server) simulate(ctx context.Context, inv ledger.Invoice, status string) (ledger.Invoice, *apiError) {
	if inv.Mode != ledger.ModeTest {
		return inv, &apiError{http.StatusForbidden, "LIVE_INVOICE", "Simulasi hanya untuk tagihan mode test"}
	}
	if status == "" {
		status = ledger.StatusPaid
	}
	if status != ledger.StatusPaid && status != ledger.StatusExpired {
		return inv, &apiError{http.StatusBadRequest, "INVALID", "status harus paid atau expired"}
	}
	if inv.Status != ledger.StatusPending {
		return inv, &apiError{http.StatusConflict, "NOT_PENDING", "Tagihan sudah " + inv.Status}
	}
	var err error
	if status == ledger.StatusPaid {
		txID, rerr := randomKey("TEST", 9)
		if rerr != nil {
			return inv, &apiError{http.StatusInternalServerError, "RANDOM", "Gagal membuat ID transaksi"}
		}
		_, err = s.Store.MarkPaid(ctx, inv.ID, strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(txID)), simulatedPaymentType, s.Now().UTC())
	} else {
		_, err = s.Store.MarkExpired(ctx, inv.ID)
	}
	if err != nil {
		return inv, &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal memperbarui tagihan"}
	}
	out, err := s.Store.GetInvoice(ctx, inv.AppID, inv.ID)
	if err != nil {
		return inv, &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan"}
	}
	if out.Status != ledger.StatusPending {
		s.notifyTransition(ctx, out)
	}
	return out, nil
}

// simulateInvoice: POST /api/v2/invoices/{id}/simulate (secret key aplikasi test).
func (s *Server) simulateInvoice(w http.ResponseWriter, r *http.Request, app ledger.App, id string) {
	var req struct {
		Status string `json:"status"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	if app.Mode != ledger.ModeTest {
		writeErr(w, http.StatusForbidden, "LIVE_MODE", "Simulasi hanya bisa dengan secret key mode test (pgk_test_…)")
		return
	}
	inv, err := s.Store.GetInvoice(r.Context(), app.ID, id)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Tagihan tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	out, apiErr := s.simulate(r.Context(), inv, strings.TrimSpace(req.Status))
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusOK, invoiceView(out))
}

// consoleTestInvoice: POST /api/v2/console/apps/{id}/test-invoice {amount, order_id?}
// Membuat tagihan uji dari console (hanya aplikasi test).
func (s *Server) consoleTestInvoice(w http.ResponseWriter, r *http.Request, app ledger.App) {
	var req struct {
		Amount  int64  `json:"amount"`
		OrderID string `json:"order_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if app.Mode != ledger.ModeTest {
		writeErr(w, http.StatusForbidden, "LIVE_MODE", "Tagihan uji hanya bisa dibuat dari aplikasi mode test")
		return
	}
	if req.Amount < 1 || req.Amount > 100_000_000 {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nominal harus antara 1 dan 100.000.000")
		return
	}
	orderID := strings.TrimSpace(req.OrderID)
	if orderID == "" {
		suffix, err := randomKey("", 6)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat order_id")
			return
		}
		orderID = "UJI-" + strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(suffix))
	}
	if len(orderID) > 100 {
		writeErr(w, http.StatusBadRequest, "INVALID", "order_id maks. 100 karakter")
		return
	}
	view, _, apiErr := s.issueInvoice(r.Context(), app, orderID, req.Amount, 10)
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

// consoleSimulate: POST /api/v2/console/apps/{id}/invoices/{invoice_id}/simulate {status}
func (s *Server) consoleSimulate(w http.ResponseWriter, r *http.Request, app ledger.App, invoiceID string) {
	var req struct {
		Status string `json:"status"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	inv, err := s.Store.GetInvoice(r.Context(), app.ID, invoiceID)
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Tagihan tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca tagihan")
		return
	}
	out, apiErr := s.simulate(r.Context(), inv, strings.TrimSpace(req.Status))
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusOK, invoiceView(out))
}
