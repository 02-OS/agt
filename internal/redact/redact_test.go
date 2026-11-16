package redact

import "strings"

import "testing"

func TestTextHidesSecretsAndKeepsCode(t *testing.T) {
	src := strings.Join([]string{
		"func charge() int { return 1 }",
		"token := config",
		"password=hunter2hunter",
		`api_key: "sk-test-secret-value"`,
		"Authorization: Bearer abcdefghijklmnop",
		"key AKIAIOSFODNN7EXAMPLE end",
		"-----BEGIN PRIVATE KEY-----",
		"not-a-real-key",
		"-----END PRIVATE KEY-----",
		"-----BEGIN PUBLIC KEY-----",
		"leave-public",
		"-----END PUBLIC KEY-----",
	}, "\n")
	out := Text(src)
	for _, secret := range []string{"hunter2hunter", "sk-test-secret-value", "abcdefghijklmnop", "AKIAIOSFODNN7EXAMPLE", "not-a-real-key"} {
		if strings.Contains(out, secret) {
			t.Fatalf("still visible %q\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "func charge() int { return 1 }") {
		t.Fatalf("code removed\n%s", out)
	}
	if !strings.Contains(out, "token := config") {
		t.Fatalf("assignment rewritten\n%s", out)
	}
	if !strings.Contains(out, "leave-public") {
		t.Fatalf("public key removed\n%s", out)
	}
}

func TestTextRedactsPrefixedEnvAndJSONPairs(t *testing.T) {
	src := strings.Join([]string{
		"OPENAI_API_KEY=sk-prefixed-env-secret",
		"DATABASE_PASSWORD=dbsecretvalue",
		`{"api_key": "json_secret_spaced", "token":"json_tok_compact"}`,
		"token := config",
	}, "\n")
	out := Text(src)
	for _, secret := range []string{"sk-prefixed-env-secret", "dbsecretvalue", "json_secret_spaced", "json_tok_compact"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked %q in:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "token := config") {
		t.Fatalf("normal Go assignment rewritten:\n%s", out)
	}
}
