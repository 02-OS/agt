package verify

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBaselineAndAcceptanceTable(t *testing.T) {
	pass := func(role, name string) CheckResult {
		return CheckResult{Name: name, Role: role, Exit: 0, Kind: KindPass}
	}
	fail := func(role, name string) CheckResult {
		return CheckResult{Name: name, Role: role, Exit: 1, Kind: KindFail}
	}
	infra := func(role, name string) CheckResult {
		return CheckResult{Name: name, Role: role, Exit: 127, Kind: KindInfrastructure, Reason: "missing executable"}
	}
	cases := []struct {
		name       string
		checks     []CheckResult
		baseline   bool
		acceptance bool
	}{
		{
			name:       "red acceptance",
			checks:     []CheckResult{pass(RoleRegression, "regress"), fail(RoleAcceptance, "accept")},
			baseline:   true,
			acceptance: false,
		},
		{
			name:       "already satisfied",
			checks:     []CheckResult{pass(RoleRegression, "regress"), pass(RoleAcceptance, "accept")},
			baseline:   false,
			acceptance: true,
		},
		{
			name:       "regression failed",
			checks:     []CheckResult{fail(RoleRegression, "regress"), fail(RoleAcceptance, "accept")},
			baseline:   false,
			acceptance: false,
		},
		{
			name:       "infrastructure",
			checks:     []CheckResult{pass(RoleRegression, "regress"), infra(RoleAcceptance, "accept")},
			baseline:   false,
			acceptance: false,
		},
		{
			name:       "acceptance only",
			checks:     []CheckResult{pass(RoleAcceptance, "accept")},
			baseline:   false,
			acceptance: true,
		},
		{
			name:       "empty",
			checks:     nil,
			baseline:   false,
			acceptance: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, summary := BaselineCheck(tc.checks)
			if ok != tc.baseline || summary == "" {
				t.Fatalf("baseline %v %q", ok, summary)
			}
			ok, summary = AcceptanceCheck(tc.checks)
			if ok != tc.acceptance || summary == "" {
				t.Fatalf("acceptance %v %q", ok, summary)
			}
		})
	}
}

func TestPropertyCheckTable(t *testing.T) {
	same := []byte("hello\n")
	other := []byte("hello\nworld\n")
	cases := []struct {
		name    string
		before  []byte
		after   []byte
		want    bool
		wantErr bool
	}{
		{name: "byte_equal", before: same, after: append([]byte(nil), same...), want: true},
		{name: "byte_equal", before: same, after: other, want: false},
		{name: "sha256_equal", before: same, after: append([]byte(nil), same...), want: true},
		{name: "sha256_equal", before: same, after: []byte("hello"), want: false},
		{name: "line_count_equal", before: same, after: []byte("other\n"), want: true},
		{name: "line_count_equal", before: same, after: other, want: false},
		{name: "line_count_equal", before: nil, after: []byte{}, want: true},
		{name: "missing", before: same, after: same, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PropertyCheck(tc.name, tc.before, tc.after)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v err %v", got, err)
			}
		})
	}
}

// fixtureSHA256 locks the trees this package reads about. The test does not
// write them. payrepo stays the published fixture.
func TestFixtureTreesStayByteForByte(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "eval", "fixtures")
	for rel, want := range fixtureSHA256 {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file", rel)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256Hex(body)
		if sum != want && runtime.GOOS == "windows" {
			// Git for Windows can check a LF blob out as CRLF. The locked
			// digest is the committed byte string. Any other edit still fails.
			lf := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
			if sha256Hex(lf) == want {
				body = lf
				sum = want
			}
		}
		if sum != want {
			t.Fatalf("%s hash changed", rel)
		}
		same, err := PropertyCheck("sha256_equal", body, body)
		if err != nil || !same {
			t.Fatalf("%s property %v %v", rel, same, err)
		}
	}
}

var fixtureSHA256 = map[string]string{
	"featuregate/greet.py":                 "5b67af0ec14c99d97817d04ac3d0d0418855bbe2a1323bc30c4beb5711c977ec",
	"featuregate/tests/__init__.py":        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"featuregate/tests/test_accept.py":     "67c041cd50a847ba66eee7ad959d53094b98e7be62f08cf1361751ba9504d414",
	"featuregate/tests/test_broken.py":     "047f96b0146c7ea16217a5d39bdc3344569dd02d5c7fa00212e3a61a2a933fb5",
	"featuregate/tests/test_other.py":      "e049def070ab8d73f4dd880582356da9f6f6ae889047e1929374ddaaebd23f04",
	"featuregate/tests/test_regress.py":    "a27ce62b70069fa947a0bed698dc0c0675c10ac57c321bedcdf88e3d09cab43d",
	"refactorgate/greet.py":                "1608f82977f2b724196438e21be98a75aff83001470425130690f017e9d7a98e",
	"refactorgate/tests/__init__.py":       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"refactorgate/tests/test_protected.py": "bdeea8346c728a21f1d8ccded27c9acc73f3c612c0a5ab25dbcd0362613a9428",
	"payrepo/README.md":                    "4d344a97f563155b33f56262984c6fe2412ccd0990853f4588486c8f6b065fa2",
	"payrepo/payments/__init__.py":         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"payrepo/payments/processor.py":        "a15f20c25a9307a850c8000d7ee3e7156902b32ec20836da7e0d2be3982a71f8",
	"payrepo/tests/__init__.py":            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"payrepo/tests/test_retry.py":          "a03781460e6889ec4b1a685e8fb66b4a0dc03e6029b279c120980763aca0b3c0",
}
