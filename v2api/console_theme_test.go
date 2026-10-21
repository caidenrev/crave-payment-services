package v2api

import (
	"context"
	"net/http"
	"testing"

	"github.com/hirotomasato/paygateme/ledger"
)

func TestConsoleCheckoutTheme(t *testing.T) {
	e := newEnv(t)
	org := e.manageEnv()
	theme := map[string]any{
		"display_name": "Kopi Senja", "logo_text": "KS", "brand_color": "#16A34A", "appearance": "dark",
		"corner": "pill", "layout": "card", "headline": "Scan untuk bayar",
		"show_timer": true, "show_wallets": false, "show_order_id": true, "show_cancel": false,
	}

	// belum ada tema: null
	code, out, _ := e.consoleCall("GET", "tok-founder", "merchants/mch_777_88/checkout-theme", nil)
	if code != http.StatusOK || out["theme"] != nil {
		t.Fatalf("empty theme: %d %v", code, out)
	}
	// simpan & baca kembali
	if code, out, raw := e.consoleCall("PUT", "tok-founder", "merchants/mch_777_88/checkout-theme", theme); code != http.StatusOK || out["success"] != true {
		t.Fatalf("save: %d %s", code, raw)
	}
	_, out, _ = e.consoleCall("GET", "tok-founder", "merchants/mch_777_88/checkout-theme", nil)
	if got := out["theme"].(map[string]any); got["brand_color"] != "#16A34A" || got["show_wallets"] != false || got["layout"] != "card" {
		t.Fatalf("read back: %v", got)
	}
	// validasi tetap berlaku
	bad := map[string]any{}
	for k, v := range theme {
		bad[k] = v
	}
	bad["brand_color"] = "hijau"
	if code, out, _ := e.consoleCall("PUT", "tok-founder", "merchants/mch_777_88/checkout-theme", bad); code != http.StatusBadRequest || out["code"] != "INVALID_THEME" {
		t.Fatalf("invalid theme: %d %v", code, out)
	}
	// org lain tidak bisa membaca / mengubah
	if code, _, _ := e.consoleCall("GET", "tok-other", "merchants/mch_777_88/checkout-theme", nil); code != http.StatusNotFound {
		t.Fatalf("foreign read: %d", code)
	}
	if code, _, _ := e.consoleCall("PUT", "tok-other", "merchants/mch_777_88/checkout-theme", theme); code != http.StatusNotFound {
		t.Fatalf("foreign write: %d", code)
	}
	// viewer hanya membaca
	_ = e.st.AddMember(context.Background(), ledger.Membership{OrgID: org, UserID: "u-viewer", Email: "v@uji.id", Role: ledger.RoleViewer})
	auth := e.srv.ConsoleAuth
	e.srv.ConsoleAuth = func(ctx context.Context, token string) (ConsoleUser, error) {
		if token == "tok-viewer" {
			return ConsoleUser{ID: "u-viewer", Email: "v@uji.id"}, nil
		}
		return auth(ctx, token)
	}
	if code, _, _ := e.consoleCall("GET", "tok-viewer", "merchants/mch_777_88/checkout-theme", nil); code != http.StatusOK {
		t.Fatalf("viewer read: %d", code)
	}
	if code, _, _ := e.consoleCall("PUT", "tok-viewer", "merchants/mch_777_88/checkout-theme", theme); code != http.StatusForbidden {
		t.Fatalf("viewer write: %d", code)
	}
}
