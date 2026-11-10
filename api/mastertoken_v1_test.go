package main

import "testing"

// master-token действует и на /v1-алиасах тех же роутов, но не шире.
func TestMasterTokenAllowedV1(t *testing.T) {
	cases := map[string]bool{
		"/admin/usage":            true,
		"/v1/admin/usage":         true,
		"/v1/admin/health":        true,
		"/v1/admin/keys/abc/revoke": true,
		"/admin/vk":               false,
		"/v1/admin/vk":            false,
		"/v1/admin/stats":         false,
	}
	for path, want := range cases {
		if got := masterTokenAllowed(path); got != want {
			t.Errorf("masterTokenAllowed(%q) = %v, want %v", path, got, want)
		}
	}
}
