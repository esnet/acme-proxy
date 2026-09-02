package acl

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeACL(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "acl.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write acl: %v", err)
	}
	return p
}

func TestACL_AllowDeny(t *testing.T) {
	p := writeACL(t, "# lab clients\n192.168.100.1\n\n# office subnet\n192.168.100.0/28\n10.0.0.0/24\n")
	SetFile(p)

	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.100.1", true},   // exact IP
		{"192.168.100.14", true},  // inside /28
		{"192.168.100.15", true},  // broadcast of /28, still contained
		{"192.168.100.16", false}, // one past the /28
		{"10.0.5.5", true},        // inside 10.0.0.0/24? no — .5.5 not in /24
		{"10.0.0.99", true},
		{"192.168.101.1", false},
		{"not-an-ip", false},
	}
	// fix the 10.0.5.5 expectation: 10.0.0.0/24 does not contain 10.0.5.5
	cases[4] = struct {
		ip   string
		want bool
	}{"10.0.5.5", false}
	for _, tc := range cases {
		if got := Allowed(tc.ip); got != tc.want {
			t.Errorf("Allowed(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestACL_DisabledAllowsAll(t *testing.T) {
	// no SetFile called in this test process state check is not possible
	// (state is global); Path()=="" implies allow-all semantics.
	if Path() == "" {
		if !Allowed("203.0.113.9") {
			t.Error("with no ACL configured, Allowed should be true")
		}
	}
}

func TestACL_HotReload(t *testing.T) {
	p := writeACL(t, "192.168.1.1\n")
	SetFile(p)
	if !Allowed("192.168.1.1") {
		t.Fatal("expected allow before edit")
	}
	// mtime granularity: force a visible change
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(p, []byte("192.168.2.2\n"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if Allowed("192.168.1.1") {
		t.Error("old entry should stop matching after reload")
	}
	if !Allowed("192.168.2.2") {
		t.Error("new entry should match after reload")
	}
}

func TestACL_ValidateAndSave(t *testing.T) {
	p := writeACL(t, "192.168.1.1\n")
	SetFile(p)

	if bad := Validate("# comment\n10.0.0.0/8\nbad-entry\n"); len(bad) != 1 || bad[0] != "bad-entry" {
		t.Errorf("Validate = %v, want [bad-entry]", bad)
	}
	if err := Save("not valid\nxxx\n"); err == nil {
		t.Error("Save with invalid entries should fail")
	}
	if err := Save("# ops\n10.1.0.0/16\n"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !Allowed("10.1.2.3") {
		t.Error("saved entry should match immediately")
	}
}

func TestACL_AllowedRequestXFF(t *testing.T) {
	p := writeACL(t, "198.51.100.7\n")
	SetFile(p)
	r := httptest.NewRequest("POST", "/new-order", nil)
	r.RemoteAddr = "10.9.9.9:1234"
	if AllowedRequest(r) {
		t.Error("remote addr not in ACL should be denied")
	}
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if !AllowedRequest(r) {
		t.Error("XFF client in ACL should be allowed")
	}
}

func TestACL_MissingFileFailsClosed(t *testing.T) {
	SetFile(filepath.Join(t.TempDir(), "gone.txt"))
	if Allowed("192.168.1.1") {
		t.Error("missing ACL file must deny (fail closed)")
	}
}
