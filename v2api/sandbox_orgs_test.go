package v2api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hirotomasato/paygateme/ledger"
	"github.com/hirotomasato/paygateme/shopee"
)

func TestConsoleCreateOrg(t *testing.T) {
	e := newEnv(t)
	e.teamEnv()
	// pengguna baru tanpa org (mis. disetujui lalu keluar) membuat org sendiri
	code, out, raw := e.consoleCall("POST", "tok-u-budi", "orgs", map[string]any{"name": "  Toko Budi  "})
	if code != http.StatusCreated || out["org"].(map[string]any)["name"] != "Toko Budi" || out["org"].(map[string]any)["role"] != "owner" {
		t.Fatalf("create org: %d %s", code, raw)
	}
	newOrg := out["org"].(map[string]any)["id"].(string)
	_, me := e.console("tok-u-budi", "me")
	if orgs := me["orgs"].([]any); len(orgs) != 1 || orgs[0].(map[string]any)["id"] != newOrg {
		t.Fatalf("me after create: %v", me)
	}
	// org baru kosong: tidak melihat merchant founder
	if _, ms := e.console("tok-u-budi", "merchants", newOrg); len(ms["merchants"].([]any)) != 0 {
		t.Fatalf("new org must be empty: %v", ms)
	}
	if code, _, _ := e.consoleCall("POST", "tok-u-budi", "orgs", map[string]any{"name": "x"}); code != http.StatusBadRequest {
		t.Fatalf("short name: %d", code)
	}
	// batas org milik sendiri
	for i := 0; i < maxOwnedOrgs-1; i++ {
		e.consoleCall("POST", "tok-u-budi", "orgs", map[string]any{"name": "Org cadangan"})
	}
	if code, out, _ := e.consoleCall("POST", "tok-u-budi", "orgs", map[string]any{"name": "Kebanyakan"}); code != http.StatusConflict || out["code"] != "ORG_LIMIT" {
		t.Fatalf("org limit: %d %v", code, out)
	}
	if code, _, _ := e.consoleCall("POST", "", "orgs", map[string]any{"name": "Anonim"}); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
}

func TestSandboxMerchantForTestApps(t *testing.T) {
	e := newEnv(t)
	e.teamEnv()
	e.srv.NewClient = func(*shopee.Session) ShopeeClient { t.Fatal("sandbox tidak boleh memanggil Shopee"); return nil }
	_, out, _ := e.consoleCall("POST", "tok-u-sari", "orgs", map[string]any{"name": "Toko Sari"})
	org := out["org"].(map[string]any)["id"].(string)

	// aplikasi live tanpa merchant ditolak; test tanpa merchant → merchant sandbox
	if code, _, _ := e.consoleCall("POST", "tok-u-sari", "apps", map[string]any{"name": "Live", "mode": "live"}, org); code != http.StatusNotFound {
		t.Fatalf("live app without merchant: %d", code)
	}
	code, a, raw := e.consoleCall("POST", "tok-u-sari", "apps", map[string]any{"name": "Coba", "mode": "test"}, org)
	if code != http.StatusCreated {
		t.Fatalf("sandbox app: %d %s", code, raw)
	}
	sandbox := a["app"].(map[string]any)["merchant_id"].(string)
	if sandbox != sandboxPrefix+org {
		t.Fatalf("sandbox merchant id: %s", sandbox)
	}
	// aplikasi test kedua memakai merchant sandbox yang sama
	_, b, _ := e.consoleCall("POST", "tok-u-sari", "apps", map[string]any{"name": "Coba 2", "mode": "test"}, org)
	if b["app"].(map[string]any)["merchant_id"] != sandbox {
		t.Fatalf("second sandbox app: %v", b)
	}
	// merchant sandbox ditandai dan hanya untuk test
	_, ms := e.console("tok-u-sari", "merchants", org)
	if l := ms["merchants"].([]any); len(l) != 1 || l[0].(map[string]any)["sandbox"] != true || !strings.HasSuffix(l[0].(map[string]any)["name"].(string), "(Sandbox)") {
		t.Fatalf("sandbox listed: %v", ms)
	}
	if code, out, _ := e.consoleCall("POST", "tok-u-sari", "apps", map[string]any{"name": "Live", "merchant_id": sandbox, "mode": "live"}, org); code != http.StatusBadRequest || out["code"] != "SANDBOX_TEST_ONLY" {
		t.Fatalf("live on sandbox: %d %v", code, out)
	}
	// alur test penuh tetap jalan di merchant sandbox
	inv := e.invoice(a["api_key"].(string), "SBX-1", 7000)
	if code, paid := e.do("POST", "/api/v2/invoices/"+inv["id"].(string)+"/simulate", a["api_key"].(string), nil); code != http.StatusOK || paid["status"] != "paid" {
		t.Fatalf("simulate on sandbox: %d %v", code, paid)
	}
	// org lain tidak bisa memakai sandbox org ini
	if m, _ := e.st.GetMerchant(context.Background(), sandbox); m.OrgID != org || m.Status != ledger.MerchantDisconnected {
		t.Fatalf("sandbox merchant: %+v", m)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "apps", map[string]any{"name": "Curang", "merchant_id": sandbox, "mode": "test"}); code != http.StatusNotFound {
		t.Fatalf("foreign sandbox: %d", code)
	}
}
