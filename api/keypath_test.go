package main

// Тест 0.9: keyIDFromPath должен понимать /v1-алиасы админ-маршрутов ключа
// (/v1/admin/keys/<id>), а не только канонические пути без префикса.

import "testing"

func TestKeyIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/admin/keys/ABC123":                     "abc123",
		"/admin/keys/abc123/":                    "abc123",
		"/admin/keys/abc123/revoke":              "abc123",
		"/admin/keys/abc123/add_traffic":         "abc123",
		"/admin/keys/abc123/unbind":              "abc123",
		"/v1/admin/keys/ABC123":                  "abc123",
		"/v1/admin/keys/abc123/":                 "abc123",
		"/v1/admin/keys/abc123/revoke":           "abc123",
		"/v1/admin/keys/abc123/add_traffic":      "abc123",
		"/v1/admin/keys/v1abc":                   "v1abc", // id, начинающийся с v1, не ломается
		"/admin/keys/":                           "",
		"/admin/other/abc":                       "",
		"/v1/admin/keys":                         "",
	}
	for path, want := range cases {
		if got := keyIDFromPath(path); got != want {
			t.Errorf("keyIDFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}
