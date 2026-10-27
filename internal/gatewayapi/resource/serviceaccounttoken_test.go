// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package resource

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

func TestServiceAccountTokenKey(t *testing.T) {
	base := ServiceAccountTokenKey("ns", "sa", []string{"a", "b"}, 3600)

	require.Equal(t, base, ServiceAccountTokenKey("ns", "sa", []string{"b", "a"}, 3600), "audience order")
	require.NotEqual(t, base, ServiceAccountTokenKey("other", "sa", []string{"a", "b"}, 3600), "namespace")
	require.NotEqual(t, base, ServiceAccountTokenKey("ns", "other", []string{"a", "b"}, 3600), "name")
	require.NotEqual(t, base, ServiceAccountTokenKey("ns", "sa", []string{"a"}, 3600), "audiences")
	require.NotEqual(t, base, ServiceAccountTokenKey("ns", "sa", []string{"a", "b"}, 7200), "expiration")
	require.NotEqual(t, ServiceAccountTokenKey("ns", "sa", []string{"a", "b"}, 1), ServiceAccountTokenKey("ns", "sa", []string{"a b"}, 1), "audience boundaries")
}

func TestServiceAccountTokenExpirationSeconds(t *testing.T) {
	tests := []struct {
		name       string
		expiration *gwapiv1.Duration
		want       int64
		wantErr    bool
	}{
		{name: "default", want: int64(DefaultServiceAccountTokenExpiration / time.Second)},
		{name: "minutes", expiration: new(gwapiv1.Duration("10m")), want: 600},
		{name: "compound", expiration: new(gwapiv1.Duration("1h30m")), want: 5400},
		{name: "invalid", expiration: new(gwapiv1.Duration("soon")), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ServiceAccountTokenExpirationSeconds(&egv1a1.OIDCServiceAccountToken{Expiration: tc.expiration})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestResourcesSortServiceAccountTokens(t *testing.T) {
	r := &Resources{ServiceAccountTokens: []*ServiceAccountToken{
		{Namespace: "b", Name: "sa", Audiences: []string{"x"}, ExpirationSeconds: 3600},
		{Namespace: "a", Name: "sa2", Audiences: []string{"x"}, ExpirationSeconds: 3600},
		{Namespace: "a", Name: "sa", Audiences: []string{"x"}, ExpirationSeconds: 7200},
		{Namespace: "a", Name: "sa", Audiences: []string{"x"}, ExpirationSeconds: 3600},
	}}

	r.Sort()

	var got []string
	for _, token := range r.ServiceAccountTokens {
		got = append(got, token.Namespace+"/"+token.Name)
	}
	require.Equal(t, []string{"a/sa", "a/sa", "a/sa2", "b/sa"}, got)
	require.Equal(t, int64(3600), r.ServiceAccountTokens[0].ExpirationSeconds)
	require.Equal(t, int64(7200), r.ServiceAccountTokens[1].ExpirationSeconds)
}

func TestServiceAccountTokensDeepCopy(t *testing.T) {
	r := &Resources{ServiceAccountTokens: []*ServiceAccountToken{
		{Namespace: "ns", Name: "sa", Audiences: []string{"x"}, Token: "t"},
	}}

	cp := r.DeepCopy()
	cp.ServiceAccountTokens[0].Audiences[0] = "changed"
	cp.ServiceAccountTokens[0].Token = "changed"

	require.Equal(t, "x", r.ServiceAccountTokens[0].Audiences[0])
	require.Equal(t, "t", r.ServiceAccountTokens[0].Token)
}
