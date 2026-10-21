package v2api

// Kelola dari console (token login Supabase + X-Org-Id):
//
//	POST   /api/v2/console/merchants/otp/request   {phone, password, channel}        → challenge_id
//	POST   /api/v2/console/merchants/otp/verify    {challenge_id, otp, static_qris?} → merchant | pilih merchant
//	POST   /api/v2/console/merchants/otp/complete  {verification_id, merchant_id, store_id?, static_qris?}
//	PUT    /api/v2/console/merchants/{id}/static-qris {static_qris}
//	POST   /api/v2/console/apps                    {name, merchant_id} → api_key (sekali) + client_key
//	PATCH  /api/v2/console/apps/{id}               {name}
//	DELETE /api/v2/console/apps/{id}
//	POST   /api/v2/console/apps/{id}/secret-key    → api_key baru (sekali)
//	POST   /api/v2/console/apps/{id}/client-key    → client_key baru
//	PUT    /api/v2/console/apps/{id}/webhook       {url} → webhook_secret
//	POST   /api/v2/console/apps/{id}/webhook/test
//
// Data login Shopee (cookie, risk token, hasil verifikasi) tidak pernah dikirim
// ke browser: disimpan terenkripsi di gateway_otp_sessions, browser hanya
// memegang ID sekali pakai. Password Shopee dan OTP tidak disimpan.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/shopee"
)

const (
	otpSessionTTL  = 10 * time.Minute
	otpRateWindow  = 15 * time.Minute
	otpRateMax     = 5
	otpMaxAttempts = 3

	otpKindChallenge    = "challenge"
	otpKindVerification = "verification"
)

func canManageMerchants(role string) bool {
	return role == ledger.RoleOwner || role == ledger.RoleAdmin
}

func canManageApps(role string) bool { return canManageMerchants(role) || role == ledger.RoleDeveloper }

func forbidden(w http.ResponseWriter) {
	writeErr(w, http.StatusForbidden, "FORBIDDEN", "Peranmu di organisasi ini tidak boleh melakukan aksi ini")
}

type challengeState struct {
	Challenge shopee.OtpChallenge `json:"challenge"`
	Attempts  int                 `json:"attempts"`
}

type verificationState struct {
	Verification shopee.OtpVerification `json:"verification"`
	StaticQris   string                 `json:"static_qris"`
	Attempts     int                    `json:"attempts"`
}

// shopeeCallTimeout membatasi satu langkah login Shopee. Batas fungsi Vercel 60 detik.
const shopeeCallTimeout = 45 * time.Second

// detached membuat context yang tidak ikut tenggat request dari platform
// (Shopee bisa lambat dari region iad1), tapi tetap dibatasi d.
func detached(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), d)
}

// saveOtp menyimpan state login terenkripsi dan mengembalikan ID sekali pakai.
func (s *Server) saveOtp(r *http.Request, org ledger.Membership, user ConsoleUser, kind string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	id, err := randomKey("otp_", 18)
	if err != nil {
		return "", err
	}
	// Tetap tersimpan walau tenggat request sudah lewat, supaya pengguna bisa mencoba lagi.
	ctx, cancel := detached(r, 5*time.Second)
	defer cancel()
	return id, s.Store.SaveOtpSession(ctx, ledger.OtpSession{
		ID: id, OrgID: org.OrgID, UserID: user.ID, Kind: kind, Data: raw, ExpiresAt: s.Now().UTC().Add(otpSessionTTL),
	})
}

// takeOtp mengambil state login sekali pakai milik pengguna ini.
func (s *Server) takeOtp(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser, id, kind string, v any) bool {
	sess, err := s.Store.TakeOtpSession(r.Context(), strings.TrimSpace(id), org.OrgID, user.ID, s.Now().UTC())
	if err == nil && sess.Kind == kind && json.Unmarshal(sess.Data, v) == nil {
		return true
	}
	if err != nil && !errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca sesi login")
		return false
	}
	writeErr(w, http.StatusGone, "OTP_SESSION_EXPIRED", "Sesi login sudah kedaluwarsa atau sudah dipakai. Minta kode OTP baru.")
	return false
}

func maskPhone(p string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, p)
	if len(digits) <= 4 {
		return "••••"
	}
	return "••••" + digits[len(digits)-4:]
}

func (s *Server) consoleOtpRequest(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
		Channel  int    `json:"channel"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Phone) == "" {
		writeErr(w, http.StatusBadRequest, "INVALID", "Nomor HP Shopee Partner wajib diisi")
		return
	}
	n, err := s.Store.CountOtpSessions(r.Context(), user.ID, s.Now().UTC().Add(-otpRateWindow))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memeriksa batas permintaan")
		return
	}
	if n >= otpRateMax {
		writeErr(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Terlalu banyak permintaan kode OTP. Coba lagi 15 menit lagi.")
		return
	}
	sctx, scancel := detached(r, shopeeCallTimeout)
	defer scancel()
	ch, err := s.shopeeLogin().RequestOtp(sctx, strings.TrimSpace(req.Phone), req.Password, req.Channel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "OTP_FAILED", err.Error())
		return
	}
	id, err := s.saveOtp(r, org, user, otpKindChallenge, challengeState{Challenge: *ch})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan sesi login")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "challenge_id": id, "channel": ch.Channel, "phone": maskPhone(ch.PhoneNumber),
		"expires_in": int(otpSessionTTL.Seconds()),
	})
}

func (s *Server) consoleOtpVerify(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	var req struct {
		ChallengeID string `json:"challenge_id"`
		OTP         string `json:"otp"`
		StaticQris  string `json:"static_qris"`
	}
	if !decode(w, r, &req) {
		return
	}
	if q := strings.TrimSpace(req.StaticQris); q != "" {
		if err := validateStatic(q); err != nil { // cek sebelum OTP dipakai
			writeErr(w, http.StatusBadRequest, "INVALID_QRIS", err.Error())
			return
		}
	}
	var st challengeState
	if !s.takeOtp(w, r, org, user, req.ChallengeID, otpKindChallenge, &st) {
		return
	}
	sctx, scancel := detached(r, shopeeCallTimeout)
	defer scancel()
	verif, err := s.shopeeLogin().VerifyOtp(sctx, st.Challenge, strings.TrimSpace(req.OTP))
	if err == nil && verif == nil {
		err = errors.New("verifikasi OTP tidak mengembalikan data")
	}
	if err != nil {
		// kode salah: beri kesempatan mencoba lagi tanpa meminta OTP baru (maks. 3x)
		st.Attempts++
		out := map[string]any{"success": false, "code": "OTP_FAILED", "error": err.Error()}
		if st.Attempts < otpMaxAttempts {
			if id, err := s.saveOtp(r, org, user, otpKindChallenge, st); err == nil {
				out["challenge_id"] = id
				out["attempts_left"] = otpMaxAttempts - st.Attempts
			}
		}
		writeJSON(w, http.StatusBadRequest, out)
		return
	}
	// OTP diterima. Login diselesaikan lewat merchants/otp/complete (request
	// terpisah), jadi verification disimpan dulu.
	id, err := s.saveOtp(r, org, user, otpKindVerification, verificationState{Verification: *verif, StaticQris: strings.TrimSpace(req.StaticQris)})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan sesi login")
		return
	}
	if one, ok := shopee.ResolveSingleMerchant(verif.Merchants); ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "VERIFIED", "verification_id": id, "merchant_id": one.ID, "merchant_name": one.Name})
		return
	}
	merchants := make([]map[string]any, 0, len(verif.Merchants))
	for _, m := range verif.Merchants {
		merchants = append(merchants, map[string]any{"id": m.ID, "name": m.Name, "active": m.IsActive})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "MERCHANT_SELECTION_NEEDED", "verification_id": id, "merchants": merchants})
}

func (s *Server) consoleOtpComplete(w http.ResponseWriter, r *http.Request, org ledger.Membership, user ConsoleUser) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	var req struct {
		VerificationID string `json:"verification_id"`
		MerchantID     string `json:"merchant_id"`
		StoreID        string `json:"store_id"`
		StaticQris     string `json:"static_qris"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.MerchantID) == "" {
		writeErr(w, http.StatusBadRequest, "INVALID", "Pilih merchant yang akan dihubungkan")
		return
	}
	var st verificationState
	if !s.takeOtp(w, r, org, user, req.VerificationID, otpKindVerification, &st) {
		return
	}
	sctx, scancel := detached(r, shopeeCallTimeout)
	defer scancel()
	sess, err := s.shopeeLogin().Complete(sctx, st.Verification, strings.TrimSpace(req.MerchantID), strings.TrimSpace(req.StoreID))
	if err != nil {
		// OTP sudah diterima; gangguan di tahap ini (mis. Shopee lambat) bisa
		// dicoba lagi tanpa meminta OTP baru (maks. 3x).
		st.Attempts++
		out := map[string]any{"success": false, "code": "LOGIN_FAILED", "error": err.Error()}
		if st.Attempts < otpMaxAttempts {
			if id, err := s.saveOtp(r, org, user, otpKindVerification, st); err == nil {
				out["verification_id"] = id
				out["attempts_left"] = otpMaxAttempts - st.Attempts
			}
		}
		writeJSON(w, http.StatusBadRequest, out)
		return
	}
	qris := strings.TrimSpace(req.StaticQris)
	if qris == "" {
		qris = st.StaticQris
	}
	s.finishConnect(w, r, org, sess, qris)
}

func (s *Server) finishConnect(w http.ResponseWriter, r *http.Request, org ledger.Membership, sess *shopee.Session, staticQris string) {
	pctx, pcancel := detached(r, 10*time.Second)
	defer pcancel()
	m, apiErr := s.persistMerchant(pctx, sess, staticQris, org.OrgID)
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": "CONNECTED", "merchant": merchantView(m)})
}

// orgMerchant memastikan merchant milik org (404 bila bukan, supaya tidak membocorkan keberadaannya).
func (s *Server) orgMerchant(w http.ResponseWriter, r *http.Request, org ledger.Membership, merchantID string) (ledger.Merchant, bool) {
	m, err := s.Store.GetMerchant(r.Context(), merchantID)
	if errors.Is(err, ledger.ErrNotFound) || (err == nil && m.OrgID != org.OrgID) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Merchant tidak ditemukan")
		return m, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca merchant")
		return m, false
	}
	return m, true
}

func (s *Server) consoleSetStaticQris(w http.ResponseWriter, r *http.Request, org ledger.Membership, merchantID string) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	if _, ok := s.orgMerchant(w, r, org, merchantID); !ok {
		return
	}
	s.setStaticQris(w, r, merchantID)
}

// consoleDisconnectMerchant logout merchant dari Shopee: sesi dihapus, status
// terputus. Merchant & aplikasinya tetap; tagihan baru ditolak sampai login ulang via OTP.
func (s *Server) consoleDisconnectMerchant(w http.ResponseWriter, r *http.Request, org ledger.Membership, merchantID string) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	if _, ok := s.orgMerchant(w, r, org, merchantID); !ok {
		return
	}
	err := s.Store.WithMerchantLock(r.Context(), merchantID, func(m *ledger.Merchant) error {
		m.SessionJSON = nil
		m.Status = ledger.MerchantDisconnected
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal memutuskan merchant")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "status": ledger.MerchantDisconnected})
}

// consoleReleaseMerchant menghapus merchant dari org. Ditolak bila masih ada
// aplikasi yang memakainya, supaya integrasi yang berjalan tidak putus diam-diam.
func (s *Server) consoleReleaseMerchant(w http.ResponseWriter, r *http.Request, org ledger.Membership, merchantID string) {
	if !canManageMerchants(org.Role) {
		forbidden(w)
		return
	}
	if _, ok := s.orgMerchant(w, r, org, merchantID); !ok {
		return
	}
	apps, err := s.Store.ListApps(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return
	}
	using := 0
	for _, a := range apps {
		if a.MerchantID == merchantID {
			using++
		}
	}
	if using > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "MERCHANT_HAS_APPS", "apps": using,
			"error": "Hapus dulu aplikasi yang memakai merchant ini"})
		return
	}
	ok, err := s.Store.ReleaseMerchant(r.Context(), merchantID, org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menghapus merchant")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Merchant tidak ditemukan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) consoleCreateApp(w http.ResponseWriter, r *http.Request, org ledger.Membership) {
	if !canManageApps(org.Role) {
		forbidden(w)
		return
	}
	var req struct {
		Name       string `json:"name"`
		MerchantID string `json:"merchant_id"`
		Mode       string `json:"mode"`
	}
	if !decode(w, r, &req) {
		return
	}
	// aplikasi test tanpa merchant: pakai merchant sandbox org
	if req.MerchantID == "" && req.Mode == ledger.ModeTest {
		id, apiErr := s.sandboxMerchant(r.Context(), org)
		if apiErr != nil {
			apiErr.write(w)
			return
		}
		req.MerchantID = id
	}
	if _, ok := s.orgMerchant(w, r, org, req.MerchantID); !ok {
		return
	}
	if isSandbox(req.MerchantID) && req.Mode != ledger.ModeTest {
		writeErr(w, http.StatusBadRequest, "SANDBOX_TEST_ONLY", "Merchant sandbox hanya untuk aplikasi mode test")
		return
	}
	app, key, apiErr := s.newApp(r.Context(), req.Name, req.MerchantID, req.Mode)
	if apiErr != nil {
		apiErr.write(w)
		return
	}
	writeJSON(w, http.StatusCreated, newAppResponse(app, key))
}

// consoleAppAction menangani aksi pada satu aplikasi milik org.
func (s *Server) consoleAppAction(w http.ResponseWriter, r *http.Request, org ledger.Membership, appID string, rest []string) {
	if !canManageApps(org.Role) {
		forbidden(w)
		return
	}
	app, err := s.Store.AppByID(r.Context(), appID)
	if err == nil {
		var m ledger.Merchant
		if m, err = s.Store.GetMerchant(r.Context(), app.MerchantID); err == nil && m.OrgID != org.OrgID {
			err = ledger.ErrNotFound
		}
	}
	if errors.Is(err, ledger.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Aplikasi tidak ditemukan")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal membaca aplikasi")
		return
	}

	action := strings.Join(rest, "/")
	switch {
	case r.Method == http.MethodPatch && action == "":
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" || len([]rune(name)) > 60 {
			writeErr(w, http.StatusBadRequest, "INVALID", "Nama aplikasi wajib diisi (maks. 60 karakter)")
			return
		}
		if err := s.Store.RenameApp(r.Context(), app.ID, name); err != nil {
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan nama aplikasi")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": app.ID, "name": name})

	case r.Method == http.MethodDelete && action == "":
		if err := s.Store.DeleteApp(r.Context(), app.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menghapus aplikasi")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": app.ID})

	case r.Method == http.MethodPost && action == "secret-key":
		key, err := newSecretKeyFor(app.Mode)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "RANDOM", "Gagal membuat API key")
			return
		}
		if err := s.Store.SetKeyHash(r.Context(), app.ID, hashKey(key)); err != nil {
			writeErr(w, http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan API key")
			return
		}
		// hanya ditampilkan sekali; key lama langsung tidak berlaku
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "app_id": app.ID, "api_key": key})

	case r.Method == http.MethodPost && action == "client-key":
		s.rollClientKey(w, r, app.ID)

	case r.Method == http.MethodPut && action == "webhook":
		s.writeWebhookUpdate(w, r, app)

	case r.Method == http.MethodPost && action == "webhook/test":
		s.testWebhook(w, r, app.ID)

	case r.Method == http.MethodGet && action == "webhook/events":
		s.writeWebhookEvents(w, r, app.ID)

	case r.Method == http.MethodPost && len(rest) == 4 && rest[0] == "webhook" && rest[1] == "events" && rest[3] == "resend":
		s.resendWebhookEvent(w, r, app, rest[2])

	case r.Method == http.MethodPost && action == "test-invoice":
		s.consoleTestInvoice(w, r, app)

	case r.Method == http.MethodPost && len(rest) == 3 && rest[0] == "invoices" && rest[2] == "simulate":
		s.consoleSimulate(w, r, app, rest[1])

	default:
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "Endpoint console tidak ditemukan")
	}
}

// consoleCheckoutTheme: GET/PUT /api/v2/console/merchants/{id}/checkout-theme
// untuk merchant milik org. Menyimpan butuh peran yang boleh mengelola aplikasi.
func (s *Server) consoleCheckoutTheme(w http.ResponseWriter, r *http.Request, org ledger.Membership, merchantID string) {
	if r.Method == http.MethodPut && !canManageApps(org.Role) {
		forbidden(w)
		return
	}
	if _, ok := s.orgMerchant(w, r, org, merchantID); !ok {
		return
	}
	if r.Method == http.MethodPut {
		s.putCheckoutTheme(w, r, merchantID)
		return
	}
	s.getCheckoutTheme(w, r, merchantID)
}
