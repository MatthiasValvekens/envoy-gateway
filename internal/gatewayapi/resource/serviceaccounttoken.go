// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package resource

import (
	"fmt"
	"slices"
	"strings"
	"time"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

// DefaultServiceAccountTokenExpiration is the lifetime requested for a ServiceAccount token
// when the API does not set one.
const DefaultServiceAccountTokenExpiration = time.Hour

// ServiceAccountToken is a token that the provider requested for a ServiceAccount with the
// Kubernetes TokenRequest API, for example to authenticate an OIDC client to its token endpoint.
// Exactly one of Token and Error is set.
// +k8s:deepcopy-gen=true
type ServiceAccountToken struct {
	// Namespace and Name identify the ServiceAccount the token was requested for.
	Namespace string `json:"namespace" yaml:"namespace"`
	Name      string `json:"name" yaml:"name"`
	// Audiences and ExpirationSeconds are the parameters of the token request.
	Audiences         []string `json:"audiences" yaml:"audiences"`
	ExpirationSeconds int64    `json:"expirationSeconds" yaml:"expirationSeconds"`
	// Token is the serialized token. It is a credential and must not be logged.
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
	// Error is why no token is available. It never contains the token.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// Key returns the identity of the token request, which is the same for every request with the
// same ServiceAccount, audiences (in any order) and expiration.
func (s *ServiceAccountToken) Key() string {
	return ServiceAccountTokenKey(s.Namespace, s.Name, s.Audiences, s.ExpirationSeconds)
}

// ServiceAccountTokenKey returns the identity of a token request. The audiences are sorted,
// so their order in the API does not matter.
func ServiceAccountTokenKey(namespace, name string, audiences []string, expirationSeconds int64) string {
	sorted := slices.Clone(audiences)
	slices.Sort(sorted)
	// The separators cannot occur in a Kubernetes name, and an audience is only compared as a whole.
	return fmt.Sprintf("%s/%s\x00%d\x00%s", namespace, name, expirationSeconds, strings.Join(sorted, "\x00"))
}

// ServiceAccountTokenExpirationSeconds returns the lifetime to request for the token, in seconds.
func ServiceAccountTokenExpirationSeconds(sat *egv1a1.OIDCServiceAccountToken) (int64, error) {
	if sat.Expiration == nil {
		return int64(DefaultServiceAccountTokenExpiration / time.Second), nil
	}
	d, err := time.ParseDuration(string(*sat.Expiration))
	if err != nil {
		return 0, fmt.Errorf("invalid expiration: %w", err)
	}
	return int64(d / time.Second), nil
}
