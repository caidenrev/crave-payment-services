package v2api

// Email operasional ke anggota organisasi (Resend), mis. saat sesi Shopee
// merchant habis dan merchant perlu login ulang lewat OTP.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
)

// Mailer mengirim satu email ke beberapa penerima.
type Mailer interface {
	Send(ctx context.Context, to []string, subject, htmlBody string) error
}

type resendMailer struct {
	apiKey, from string
	client       *http.Client
}

func (m resendMailer) Send(ctx context.Context, to []string, subject, htmlBody string) error {
	raw, _ := json.Marshal(map[string]any{"from": m.from, "to": to, "subject": subject, "html": htmlBody})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("resend: HTTP %d %s", resp.StatusCode, body)
	}
	return nil
}

func (s *Server) mailer() Mailer {
	if s.Mail != nil {
		return s.Mail
	}
	if s.ResendAPIKey == "" {
		return nil
	}
	from := s.EmailFrom
	if from == "" {
		from = "Crave Pay <no-reply@craveservices.my.id>"
	}
	return resendMailer{apiKey: s.ResendAPIKey, from: from, client: &http.Client{Timeout: 6 * time.Second}}
}

// nullTime: nil untuk waktu kosong (JSON null), selain itu waktunya.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// notifyMerchantExpired mengirim email ke owner/admin org merchant. Gagal kirim
// tidak memengaruhi tagihan; dashboard tetap menandai merchant "Perlu Login".
func (s *Server) notifyMerchantExpired(ctx context.Context, m ledger.Merchant) {
	mail := s.mailer()
	if mail == nil || m.OrgID == "" {
		return
	}
	members, err := s.Store.MembersOfOrg(ctx, m.OrgID)
	if err != nil {
		return
	}
	var to []string
	for _, mb := range members {
		if (mb.Role == ledger.RoleOwner || mb.Role == ledger.RoleAdmin) && mb.Email != "" {
			to = append(to, mb.Email)
		}
	}
	if len(to) == 0 {
		return
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Second)
	defer cancel()
	name := html.EscapeString(m.Name)
	body := `<div style="font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#F3F6FA;padding:28px 16px">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:20px;border:1px solid #E2E8F0;padding:28px">
<p style="margin:0 0 6px;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:#D97706">Perlu tindakan</p>
<h1 style="margin:0 0 12px;font-size:20px;color:#0F172A">` + name + ` terputus dari Shopee</h1>
<p style="margin:0 0 12px;font-size:14px;line-height:1.65;color:#475569">Sesi Shopee Partner merchant ini sudah habis, jadi pembayaran QRIS baru belum bisa dideteksi otomatis dan tagihan baru ditolak.</p>
<p style="margin:0;font-size:14px;line-height:1.65;color:#475569">Buka tab <b>Merchant</b> di console, lalu pilih <b>Login ulang</b> dan masukkan kode OTP.</p>
<p style="margin:22px 0 0"><a href="https://pay.craveservices.my.id/dashboard" style="display:inline-block;background:#2D3FE7;color:#fff;text-decoration:none;font-weight:700;font-size:13px;padding:11px 20px;border-radius:12px">Login ulang merchant</a></p>
<p style="margin:16px 0 0;font-size:11.5px;color:#94A3B8">Email ini dikirim ke owner dan admin organisasi.</p>
</div></div>`
	_ = mail.Send(sendCtx, to, m.Name+" terputus dari Shopee, perlu login ulang", body)
}
