package v2api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestConsoleWebhookLogAndResend(t *testing.T) {
	e := newEnv(t)
	_, test, appID, rc := e.testModeEnv()
	rc.mu.Lock()
	rc.status = []int{500} // kiriman pertama ditolak server toko
	rc.mu.Unlock()

	inv := e.invoice(test, "LOG-1", 12000)
	if code, _ := e.do("POST", "/api/v2/invoices/"+inv["id"].(string)+"/simulate", test, nil); code != http.StatusOK {
		t.Fatalf("simulate: %d", code)
	}

	// log: event gagal dengan kode 500, payload ikut
	code, out, raw := e.consoleCall("GET", "tok-founder", "apps/"+appID+"/webhook/events", nil)
	if code != http.StatusOK {
		t.Fatalf("events: %d %s", code, raw)
	}
	evs := out["events"].([]any)
	ev := evs[0].(map[string]any)
	if len(evs) != 1 || ev["type"] != "invoice.paid" || ev["status"] != "pending" || ev["last_status"] != float64(500) || ev["last_attempt_at"] == nil {
		t.Fatalf("failed event: %v", ev)
	}
	payload, _ := json.Marshal(ev["payload"])
	if !strings.Contains(string(payload), `"order_id":"LOG-1"`) {
		t.Fatalf("payload: %s", payload)
	}
	evID := ev["id"].(string)

	// kirim ulang manual: berhasil → terkirim
	code, res, raw := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/webhook/events/"+evID+"/resend", nil)
	if code != http.StatusOK || res["success"] != true || res["status"] != "delivered" || res["last_status"] != float64(200) || res["attempts"] != float64(2) {
		t.Fatalf("resend: %d %s", code, raw)
	}
	calls := rc.calls()
	if len(calls) != 2 || calls[1].eventID != evID {
		t.Fatalf("receiver calls: %+v", calls)
	}
	// event yang sudah terkirim tetap boleh dikirim ulang (replay)
	if code, res, _ := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/webhook/events/"+evID+"/resend", nil); code != http.StatusOK || res["status"] != "delivered" {
		t.Fatalf("replay: %d %v", code, res)
	}

	// gagal saat kirim ulang: dicatat, status tidak berubah
	rc.mu.Lock()
	rc.status = []int{503}
	rc.mu.Unlock()
	if _, res, _ := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/webhook/events/"+evID+"/resend", nil); res["success"] != false || res["status"] != "delivered" || res["last_status"] != float64(503) {
		t.Fatalf("failed resend: %v", res)
	}

	// org lain & event tak dikenal
	if code, _, _ := e.consoleCall("GET", "tok-other", "apps/"+appID+"/webhook/events", nil); code != http.StatusNotFound {
		t.Fatalf("foreign log: %d", code)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "apps/"+appID+"/webhook/events/evt_tidakada/resend", nil); code != http.StatusNotFound {
		t.Fatalf("unknown event: %d", code)
	}
}
