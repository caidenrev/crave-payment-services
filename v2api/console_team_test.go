package v2api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/hirotomasato/paygateme/ledger"
)

// fakeInviter: email baru → user baru + email terkirim; "lama@uji.id" → akun sudah aktif.
type fakeInviter struct{ sent []string }

func (f *fakeInviter) Invite(_ context.Context, email string) (string, bool, error) {
	if email == "penuh@uji.id" {
		return "", false, errInviteRateLimited
	}
	if email == "lama@uji.id" {
		return "u-lama", true, nil
	}
	f.sent = append(f.sent, email)
	return "u-" + strings.Split(email, "@")[0], false, nil
}

// teamEnv: founder (owner) + tok-<nama> untuk tiap pengguna undangan.
func (e *env) teamEnv() (*fakeInviter, string) {
	org := e.manageEnv()
	inv := &fakeInviter{}
	e.srv.Inviter = inv
	auth := e.srv.ConsoleAuth
	e.srv.ConsoleAuth = func(ctx context.Context, token string) (ConsoleUser, error) {
		if name, ok := strings.CutPrefix(token, "tok-u-"); ok {
			return ConsoleUser{ID: "u-" + name, Email: name + "@uji.id"}, nil
		}
		return auth(ctx, token)
	}
	return inv, org
}

func memberByEmail(t *testing.T, out map[string]any, email string) map[string]any {
	t.Helper()
	for _, raw := range out["members"].([]any) {
		if m := raw.(map[string]any); m["email"] == email {
			return m
		}
	}
	return nil
}

func TestConsoleInviteAndJoin(t *testing.T) {
	e := newEnv(t)
	inv, _ := e.teamEnv()

	code, out, raw := e.consoleCall("POST", "tok-founder", "members", map[string]any{"email": " Dev@Uji.id ", "role": "developer"})
	if code != http.StatusCreated || out["email_sent"] != true || len(inv.sent) != 1 || inv.sent[0] != "dev@uji.id" {
		t.Fatalf("invite: %d %s", code, raw)
	}
	_, list, _ := e.consoleCall("GET", "tok-founder", "members", nil)
	if m := memberByEmail(t, list, "dev@uji.id"); m == nil || m["status"] != "invited" || m["role"] != "developer" || m["invited_by"] != founderEmail {
		t.Fatalf("invited member: %v", list)
	}
	if list["invites_enabled"] != true {
		t.Fatalf("invites must be enabled with an inviter")
	}
	// anggota yang sama tidak bisa diundang dua kali
	if code, out, _ := e.consoleCall("POST", "tok-founder", "members", map[string]any{"email": "dev@uji.id", "role": "viewer"}); code != http.StatusConflict || out["code"] != "ALREADY_MEMBER" {
		t.Fatalf("duplicate invite: %d %v", code, out)
	}
	// kirim ulang undangan selama belum bergabung
	if code, _, _ := e.consoleCall("POST", "tok-founder", "members/u-dev/resend", nil); code != http.StatusOK || len(inv.sent) != 2 {
		t.Fatalf("resend: %d", code)
	}

	// pengguna undangan membuka console → bergabung & bisa membaca data org
	if code, _ := e.console("tok-u-dev", "merchants"); code != http.StatusOK {
		t.Fatalf("invited user can open the console: %d", code)
	}
	_, list, _ = e.consoleCall("GET", "tok-founder", "members", nil)
	if m := memberByEmail(t, list, "dev@uji.id"); m["status"] != "active" || m["joined_at"] == nil {
		t.Fatalf("member must be active after first visit: %v", m)
	}
	if code, out, _ := e.consoleCall("POST", "tok-founder", "members/u-dev/resend", nil); code != http.StatusConflict || out["code"] != "ALREADY_JOINED" {
		t.Fatalf("resend after join: %d %v", code, out)
	}

	// akun yang sudah ada: ditambahkan tanpa email
	if code, out, _ := e.consoleCall("POST", "tok-founder", "members", map[string]any{"email": "lama@uji.id", "role": "viewer"}); code != http.StatusCreated || out["email_sent"] != false {
		t.Fatalf("existing account: %d %v", code, out)
	}
	// batas kirim Supabase → 429
	if code, _, _ := e.consoleCall("POST", "tok-founder", "members", map[string]any{"email": "penuh@uji.id", "role": "viewer"}); code != http.StatusTooManyRequests {
		t.Fatalf("rate limited: %d", code)
	}
	// email & peran tidak valid
	for _, body := range []map[string]any{{"email": "bukan-email", "role": "viewer"}, {"email": "x@uji.id", "role": "dewa"}} {
		if code, _, _ := e.consoleCall("POST", "tok-founder", "members", body); code != http.StatusBadRequest {
			t.Fatalf("invalid invite %v: %d", body, code)
		}
	}
}

func TestConsoleTeamPermissions(t *testing.T) {
	e := newEnv(t)
	_, org := e.teamEnv()
	ctx := context.Background()
	for _, m := range []ledger.Membership{
		{OrgID: org, UserID: "u-admin", Email: "admin@uji.id", Role: ledger.RoleAdmin},
		{OrgID: org, UserID: "u-dev", Email: "dev@uji.id", Role: ledger.RoleDeveloper},
		{OrgID: org, UserID: "u-viewer", Email: "viewer@uji.id", Role: ledger.RoleViewer},
	} {
		_ = e.st.AddMember(ctx, m)
	}
	_, me := e.console("tok-founder", "me")
	founderID := me["user"].(map[string]any)["id"].(string)

	// developer & viewer tidak bisa mengundang; semua anggota bisa melihat daftar
	if code, _, _ := e.consoleCall("POST", "tok-u-dev", "members", map[string]any{"email": "a@uji.id", "role": "viewer"}); code != http.StatusForbidden {
		t.Fatalf("developer invite: %d", code)
	}
	if code, _, _ := e.consoleCall("GET", "tok-u-viewer", "members", nil); code != http.StatusOK {
		t.Fatalf("viewer list: %d", code)
	}
	// admin tidak bisa mengundang/menjadikan owner, atau mengubah owner
	if code, _, _ := e.consoleCall("POST", "tok-u-admin", "members", map[string]any{"email": "b@uji.id", "role": "owner"}); code != http.StatusForbidden {
		t.Fatalf("admin invites owner: %d", code)
	}
	if code, _, _ := e.consoleCall("PATCH", "tok-u-admin", "members/u-dev", map[string]any{"role": "owner"}); code != http.StatusForbidden {
		t.Fatalf("admin promotes to owner: %d", code)
	}
	if code, _, _ := e.consoleCall("DELETE", "tok-u-admin", "members/"+founderID, nil); code != http.StatusForbidden {
		t.Fatalf("admin removes owner: %d", code)
	}
	// admin boleh mengubah developer → viewer
	if code, out, _ := e.consoleCall("PATCH", "tok-u-admin", "members/u-dev", map[string]any{"role": "viewer"}); code != http.StatusOK || out["member"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("admin demotes developer: %d %v", code, out)
	}
	// tidak bisa mengubah peran sendiri
	if code, _, _ := e.consoleCall("PATCH", "tok-founder", "members/"+founderID, map[string]any{"role": "viewer"}); code != http.StatusBadRequest {
		t.Fatalf("self role change: %d", code)
	}
	// owner terakhir tidak bisa keluar
	if code, out, _ := e.consoleCall("DELETE", "tok-founder", "members/"+founderID, nil); code != http.StatusConflict || out["code"] != "LAST_OWNER" {
		t.Fatalf("last owner leaves: %d %v", code, out)
	}
	// owner menjadikan admin owner kedua, lalu owner pertama boleh keluar
	if code, _, _ := e.consoleCall("PATCH", "tok-founder", "members/u-admin", map[string]any{"role": "owner"}); code != http.StatusOK {
		t.Fatalf("promote admin: %d", code)
	}
	// anggota yang dikeluarkan langsung kehilangan akses
	if code, _, _ := e.consoleCall("DELETE", "tok-u-admin", "members/u-dev", nil); code != http.StatusOK {
		t.Fatalf("remove developer: %d", code)
	}
	if code, _ := e.console("tok-u-dev", "merchants"); code != http.StatusForbidden {
		t.Fatalf("removed member loses access: %d", code)
	}
	if code, _, _ := e.consoleCall("DELETE", "tok-founder", "members/"+founderID, nil); code != http.StatusOK {
		t.Fatalf("owner leaves with another owner: %d", code)
	}
	// viewer boleh keluar sendiri; org lain tidak bisa menyentuh anggota org ini
	if code, _, _ := e.consoleCall("DELETE", "tok-other", "members/u-viewer", nil); code != http.StatusNotFound {
		t.Fatalf("foreign remove: %d", code)
	}
	if code, _, _ := e.consoleCall("DELETE", "tok-u-viewer", "members/u-viewer", nil); code != http.StatusOK {
		t.Fatalf("viewer leaves: %d", code)
	}
}

func TestConsoleInvitesDisabledWithoutServiceKey(t *testing.T) {
	e := newEnv(t)
	e.manageEnv()
	_, list, _ := e.consoleCall("GET", "tok-founder", "members", nil)
	if list["invites_enabled"] != false {
		t.Fatalf("invites must be disabled without a service key: %v", list)
	}
	if code, out, _ := e.consoleCall("POST", "tok-founder", "members", map[string]any{"email": "a@uji.id", "role": "viewer"}); code != http.StatusServiceUnavailable || out["code"] != "INVITES_DISABLED" {
		t.Fatalf("invite without key: %d %v", code, out)
	}
}
