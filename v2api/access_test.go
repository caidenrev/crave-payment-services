package v2api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hirotomasato/paygateme/ledger"
)

type fakeNotifier struct{ sent []string }

func (f *fakeNotifier) Notify(_ context.Context, subject, htmlBody, replyTo string) error {
	f.sent = append(f.sent, subject+"|"+replyTo+"|"+htmlBody)
	return nil
}

func accessBody(email string) map[string]any {
	return map[string]any{
		"name": "Budi <Santoso>", "email": email, "phone": "0812-3456-7890",
		"company": "Toko Budi", "reason": "Mau terima QRIS di aplikasi booking saya.",
	}
}

func (e *env) submitAccess(ip string, body map[string]any) (int, map[string]any) {
	e.t.Helper()
	return e.doH("POST", "/api/v2/public/access-requests", map[string]string{"X-Forwarded-For": ip + ", 10.0.0.1"}, body)
}

func TestAccessRequestSubmit(t *testing.T) {
	e := newEnv(t)
	e.consoleEnv()
	n := &fakeNotifier{}
	e.srv.Notifier = n

	if code, _ := e.submitAccess("1.1.1.1", accessBody("Budi@Uji.id")); code != http.StatusCreated {
		t.Fatalf("submit: %d", code)
	}
	list, _ := e.st.ListAccessRequests(context.Background(), "", 10)
	if len(list) != 1 || list[0].Email != "budi@uji.id" || list[0].Status != ledger.AccessPending || list[0].IPHash == "" || strings.Contains(list[0].IPHash, "1.1.1.1") {
		t.Fatalf("stored request: %+v", list)
	}
	// email pemberitahuan: balas ke pemohon, isi di-escape
	htmlPart := n.sent[0][strings.Index(n.sent[0], "|budi@uji.id|")+len("|budi@uji.id|"):]
	if len(n.sent) != 1 || !strings.Contains(htmlPart, "Budi &lt;Santoso&gt;") || strings.Contains(htmlPart, "<Santoso>") {
		t.Fatalf("notification: %v", n.sent)
	}
	// permintaan yang sama masih menunggu: tidak dobel, tidak kirim email lagi
	if code, _ := e.submitAccess("2.2.2.2", accessBody("budi@uji.id")); code != http.StatusOK || len(n.sent) != 1 {
		t.Fatalf("duplicate: %d sent=%d", code, len(n.sent))
	}
	// jebakan bot: berhasil palsu, tidak disimpan
	bot := accessBody("bot@uji.id")
	bot["website"] = "http://spam"
	if code, _ := e.submitAccess("3.3.3.3", bot); code != http.StatusOK {
		t.Fatalf("honeypot: %d", code)
	}
	if list, _ := e.st.ListAccessRequests(context.Background(), "", 10); len(list) != 1 {
		t.Fatalf("honeypot must not be stored: %d", len(list))
	}
	// validasi
	for field, val := range map[string]any{"email": "bukan-email", "phone": "12", "reason": "pendek", "name": "B"} {
		b := accessBody("v@uji.id")
		b[field] = val
		if code, out := e.submitAccess("4.4.4.4", b); code != http.StatusBadRequest {
			t.Fatalf("invalid %s: %d %v", field, code, out)
		}
	}
	// batas 3 per IP per jam
	for i, email := range []string{"a@uji.id", "b@uji.id"} {
		if code, _ := e.submitAccess("1.1.1.1", accessBody(email)); code != http.StatusCreated {
			t.Fatalf("submit %d: %d", i, code)
		}
	}
	if code, out := e.submitAccess("1.1.1.1", accessBody("c@uji.id")); code != http.StatusTooManyRequests || out["code"] != "RATE_LIMITED" {
		t.Fatalf("rate limit: %d %v", code, out)
	}
}

func TestAccessRequestApprove(t *testing.T) {
	e := newEnv(t)
	inv, founderOrg := e.teamEnv()
	e.submitAccess("1.1.1.1", accessBody("budi@uji.id"))
	e.submitAccess("1.1.1.2", accessBody("sari@uji.id"))

	// hanya platform admin (owner/admin org founder)
	if code, _, _ := e.consoleCall("GET", "tok-other", "access-requests", nil); code != http.StatusForbidden {
		t.Fatalf("other org must not see requests: %d", code)
	}
	_ = e.st.AddMember(context.Background(), ledger.Membership{OrgID: founderOrg, UserID: "u-dev", Email: "dev@uji.id", Role: ledger.RoleDeveloper})
	if code, _, _ := e.consoleCall("GET", "tok-u-dev", "access-requests", nil); code != http.StatusForbidden {
		t.Fatalf("developer must not see requests: %d", code)
	}
	code, out, _ := e.consoleCall("GET", "tok-founder", "access-requests?status=pending", nil)
	reqs := out["requests"].([]any)
	if code != http.StatusOK || len(reqs) != 2 || out["invites_enabled"] != true {
		t.Fatalf("list: %d %v", code, out)
	}
	var budiID, sariID string
	for _, raw := range reqs {
		r := raw.(map[string]any)
		if r["email"] == "budi@uji.id" {
			budiID = r["id"].(string)
		} else {
			sariID = r["id"].(string)
		}
	}

	// setujui: org BARU milik pemohon, diundang sebagai owner
	code, out, raw := e.consoleCall("POST", "tok-founder", "access-requests/"+budiID+"/approve", map[string]any{})
	if code != http.StatusOK || out["org"].(map[string]any)["name"] != "Toko Budi" {
		t.Fatalf("approve: %d %s", code, raw)
	}
	if d := inv.data[len(inv.data)-1]; d.OrgName != "Toko Budi" || d.RoleLabel != "Owner" || d.InvitedBy != founderEmail {
		t.Fatalf("invite data: %+v", d)
	}
	newOrg := out["org"].(map[string]any)["id"].(string)
	if newOrg == founderOrg {
		t.Fatal("requester must get their own org")
	}
	_, me := e.console("tok-u-budi", "me")
	orgs := me["orgs"].([]any)
	if len(orgs) != 1 || orgs[0].(map[string]any)["id"] != newOrg || orgs[0].(map[string]any)["role"] != "owner" {
		t.Fatalf("requester orgs: %v", me)
	}
	// pemohon tidak melihat merchant founder
	if _, ms := e.console("tok-u-budi", "merchants"); len(ms["merchants"].([]any)) != 0 {
		t.Fatalf("requester must not see founder merchants: %v", ms)
	}
	if code, _, _ := e.consoleCall("POST", "tok-founder", "access-requests/"+budiID+"/approve", nil); code != http.StatusConflict {
		t.Fatalf("approve twice: %d", code)
	}

	// tolak
	if code, _, _ := e.consoleCall("POST", "tok-founder", "access-requests/"+sariID+"/reject", nil); code != http.StatusOK {
		t.Fatalf("reject: %d", code)
	}
	_, out, _ = e.consoleCall("GET", "tok-founder", "access-requests?status=rejected", nil)
	if l := out["requests"].([]any); len(l) != 1 || l[0].(map[string]any)["decided_by"] != founderEmail {
		t.Fatalf("rejected list: %v", out)
	}
}
