package main

import "testing"

func TestRolePermissions(t *testing.T) {
	cases := []struct {
		role, perm string
		want       bool
	}{
		{"viewer", "accounts:read", true},
		{"viewer", "deal_value:read", false}, // privacy: viewers never see money
		{"viewer", "opportunities:write", false},
		{"rep", "opportunities:write", true},
		{"rep", "audit:read", false},
		{"manager", "audit:read", true},
		{"admin", "users:manage", true},
		{"ghost", "accounts:read", false}, // unknown role => deny by default
	}
	for _, c := range cases {
		if got := hasPerm(c.role, c.perm); got != c.want {
			t.Errorf("hasPerm(%s,%s)=%v want %v", c.role, c.perm, got, c.want)
		}
	}
}
