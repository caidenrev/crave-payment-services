package v2api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/shopee"
	"github.com/hirotomasato/paygateme/utils"
)

// ShopeeLogin adalah langkah login OTP Shopee Partner (palsu di tes).
type ShopeeLogin interface {
	RequestOtp(ctx context.Context, phone, password string, channel int) (*shopee.OtpChallenge, error)
	// VerifyOtp mengembalikan sesi, atau verification bila akun punya beberapa
	// merchant dan pengguna harus memilih.
	VerifyOtp(ctx context.Context, ch shopee.OtpChallenge, otp string) (*shopee.Session, *shopee.OtpVerification, error)
	Complete(ctx context.Context, v shopee.OtpVerification, merchantID, storeID string) (*shopee.Session, error)
}

type realShopeeLogin struct{}

func (realShopeeLogin) RequestOtp(ctx context.Context, phone, password string, channel int) (*shopee.OtpChallenge, error) {
	logger := utils.NewConsoleLogger(utils.LevelInfo)
	auth := shopee.NewAuthClient(shopee.NewHTTPClient(logger), shopee.APILocale{}, logger)
	return auth.RequestOtp(ctx, phone, shopee.OtpRequestOptions{Password: password, Channel: channel, DeviceReport: shopee.DeviceRiskBlob})
}

func newLoginProvider() *shopee.Provider {
	return shopee.NewProvider(shopee.ProviderConfig{DeviceReport: shopee.DeviceRiskBlob, Logger: utils.NewConsoleLogger(utils.LevelInfo)})
}

// withStore memilih outlet pertama bila sesi belum punya store.
func withStore(ctx context.Context, p *shopee.Provider, sess *shopee.Session) *shopee.Session {
	if sess.StoreID != "" {
		return sess
	}
	if stores, _ := p.ListStores(ctx); len(stores) > 0 {
		if _, err := p.SelectStore(ctx, stores[0].ID); err == nil {
			if s := p.ExportSession(); s != nil {
				return s
			}
		}
	}
	return sess
}

func (realShopeeLogin) VerifyOtp(ctx context.Context, ch shopee.OtpChallenge, otp string) (*shopee.Session, *shopee.OtpVerification, error) {
	p := newLoginProvider()
	out, err := p.LoginWithOtp(ctx, shopee.LoginWithOtpInput{Challenge: ch, OTP: otp})
	if err != nil {
		return nil, nil, err
	}
	if out.Status == shopee.LoginMerchantSelectionNeeded {
		return nil, out.Verification, nil
	}
	if out.Session == nil {
		return nil, nil, errors.New("login berhasil tetapi sesi tidak terbentuk")
	}
	return withStore(ctx, p, out.Session), nil, nil
}

func (realShopeeLogin) Complete(ctx context.Context, v shopee.OtpVerification, merchantID, storeID string) (*shopee.Session, error) {
	p := newLoginProvider()
	sess, err := p.CompleteLogin(ctx, shopee.CompleteLoginInput{Verification: v, MerchantID: merchantID, StoreID: storeID})
	if err != nil {
		return nil, err
	}
	return withStore(ctx, p, sess), nil
}

func (s *Server) shopeeLogin() ShopeeLogin {
	if s.Login != nil {
		return s.Login
	}
	return realShopeeLogin{}
}

// apiError adalah error yang sudah punya status HTTP dan kode untuk klien.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) write(w http.ResponseWriter) { writeErr(w, e.status, e.code, e.msg) }

// persistMerchant menyimpan sesi Shopee yang baru login sebagai merchant.
// orgID "" (alur admin) tidak menyentuh kepemilikan; selain itu merchant
// diberikan ke org tersebut dan merchant milik org lain ditolak.
func (s *Server) persistMerchant(ctx context.Context, sess *shopee.Session, staticQris, orgID string) (ledger.Merchant, *apiError) {
	raw, err := json.Marshal(sess)
	if err != nil {
		return ledger.Merchant{}, &apiError{http.StatusInternalServerError, "SESSION_ENCODE", err.Error()}
	}
	m := ledger.Merchant{
		ID: merchantKey(sess), Name: sess.Merchant.Name, ShopeeMerchantID: sess.Merchant.ID,
		StoreID: sess.StoreID, SessionJSON: raw, Status: ledger.MerchantConnected,
	}
	if existing, err := s.Store.GetMerchant(ctx, m.ID); err == nil {
		if orgID != "" && existing.OrgID != "" && existing.OrgID != orgID {
			return m, &apiError{http.StatusConflict, "MERCHANT_OWNED", "Merchant ini sudah terhubung ke organisasi lain"}
		}
		m.StaticQris = existing.StaticQris // login ulang tidak menghapus QRIS statis yang sudah diatur
	}
	if q := strings.TrimSpace(staticQris); q != "" {
		if err := validateStatic(q); err != nil {
			return m, &apiError{http.StatusBadRequest, "INVALID_QRIS", err.Error()}
		}
		m.StaticQris = q
	}
	if err := s.Store.SaveMerchant(ctx, m); err != nil {
		return m, &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal menyimpan merchant"}
	}
	if orgID != "" {
		ok, err := s.Store.SetMerchantOrg(ctx, m.ID, orgID)
		if err != nil {
			return m, &apiError{http.StatusInternalServerError, "STORE_ERROR", "Gagal menautkan merchant"}
		}
		if !ok {
			return m, &apiError{http.StatusConflict, "MERCHANT_OWNED", "Merchant ini sudah terhubung ke organisasi lain"}
		}
		m.OrgID = orgID
	}
	return m, nil
}
