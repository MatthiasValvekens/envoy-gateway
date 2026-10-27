// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/logging"
)

const (
	// serviceAccountTokenRefreshFraction is the share of a token's lifetime after which it is
	// replaced, the same as the kubelet does for projected tokens.
	serviceAccountTokenRefreshFraction = 0.8
	// serviceAccountTokenRetryInterval is how long to wait before requesting a token again after
	// a failure. RBAC is not watched, so a fixed retry is how a newly granted Role is noticed.
	serviceAccountTokenRetryInterval = 30 * time.Second
	// minServiceAccountTokenRequeue keeps a token that was issued with a very short lifetime
	// from causing a tight reconcile loop.
	minServiceAccountTokenRequeue = time.Second
)

// serviceAccountTokenMinter requests a token for the ServiceAccount from the API server.
// It returns the token and the time the API server says it expires.
type serviceAccountTokenMinter func(
	ctx context.Context, namespace, name string, audiences []string, expirationSeconds int64,
) (token string, expiresAt time.Time, err error)

// serviceAccountTokenCache holds the tokens requested for ServiceAccounts, so that a reconcile
// reuses a token instead of requesting a new one. A new token changes the resources, which would
// make every reconcile translate the whole configuration again.
//
// A token is requested again once serviceAccountTokenRefreshFraction of its lifetime has passed.
// The entries used by a reconcile are tracked between begin and end, and the others are dropped.
type serviceAccountTokenCache struct {
	mu      sync.Mutex
	now     func() time.Time
	mint    serviceAccountTokenMinter
	entries map[string]*serviceAccountTokenEntry
	used    map[string]struct{}
}

type serviceAccountTokenEntry struct {
	token     string
	expiresAt time.Time
	// err is why the last request failed, if it did.
	err string
	// nextAttempt is when to request a token again: when the token is due for renewal, or
	// when to retry after a failed request.
	nextAttempt time.Time
}

func newServiceAccountTokenCache(now func() time.Time, mint serviceAccountTokenMinter) *serviceAccountTokenCache {
	return &serviceAccountTokenCache{
		now:     now,
		mint:    mint,
		entries: make(map[string]*serviceAccountTokenEntry),
		used:    make(map[string]struct{}),
	}
}

// begin starts a reconcile. The entries that get is not called for until end are dropped by end.
func (c *serviceAccountTokenCache) begin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.used = make(map[string]struct{})
}

// end finishes a reconcile. It drops the entries that the reconcile did not use, and returns
// when to reconcile again for the tokens that it did use. It returns 0 if there are none.
func (c *serviceAccountTokenCache) end() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	var next time.Time
	for key, entry := range c.entries {
		if _, ok := c.used[key]; !ok {
			delete(c.entries, key)
			continue
		}
		if next.IsZero() || entry.nextAttempt.Before(next) {
			next = entry.nextAttempt
		}
	}
	if next.IsZero() {
		return 0
	}
	return max(next.Sub(c.now()), minServiceAccountTokenRequeue)
}

// get returns the token for the ServiceAccount, requesting a new one if the cached one is due for
// renewal. If the request fails, the cached token is returned as long as it has not expired.
// Otherwise the returned value carries the error instead.
func (c *serviceAccountTokenCache) get(
	ctx context.Context, log logging.Logger, namespace, name string, audiences []string, expirationSeconds int64,
) *resource.ServiceAccountToken {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := resource.ServiceAccountTokenKey(namespace, name, audiences, expirationSeconds)
	c.used[key] = struct{}{}

	now := c.now()
	entry := c.entries[key]
	if entry == nil || !now.Before(entry.nextAttempt) {
		entry = c.renew(ctx, log, key, entry, namespace, name, audiences, expirationSeconds, now)
	}

	sorted := slices.Clone(audiences)
	slices.Sort(sorted)
	result := &resource.ServiceAccountToken{
		Namespace:         namespace,
		Name:              name,
		Audiences:         sorted,
		ExpirationSeconds: expirationSeconds,
	}
	if entry.token != "" && now.Before(entry.expiresAt) {
		result.Token = entry.token
	} else {
		result.Error = entry.err
	}
	return result
}

// renew requests a new token and updates the entry for it. It must be called with c.mu held.
func (c *serviceAccountTokenCache) renew(
	ctx context.Context, log logging.Logger, key string, entry *serviceAccountTokenEntry,
	namespace, name string, audiences []string, expirationSeconds int64, now time.Time,
) *serviceAccountTokenEntry {
	token, expiresAt, err := c.mint(ctx, namespace, name, audiences, expirationSeconds)
	if err == nil && !expiresAt.After(now) {
		err = errors.New("the API server returned a token that has already expired")
	}

	if entry == nil {
		entry = &serviceAccountTokenEntry{}
		c.entries[key] = entry
	}

	if err != nil {
		entry.err = describeServiceAccountTokenError(err, namespace, name)
		entry.nextAttempt = now.Add(serviceAccountTokenRetryInterval)
		log.Error(err, "failed to request a ServiceAccount token",
			"namespace", namespace, "name", name, "retryIn", serviceAccountTokenRetryInterval)
		return entry
	}

	// Renew after a share of the lifetime that the API server granted, which can differ
	// from the one that was requested.
	lifetime := expiresAt.Sub(now)
	entry.token = token
	entry.expiresAt = expiresAt
	entry.err = ""
	entry.nextAttempt = now.Add(time.Duration(float64(lifetime) * serviceAccountTokenRefreshFraction))
	return entry
}

// describeServiceAccountTokenError returns the message for the status of the SecurityPolicy that
// needs the token. It never contains a token.
func describeServiceAccountTokenError(err error, namespace, name string) string {
	if kerrors.IsForbidden(err) {
		return fmt.Sprintf(
			"forbidden: grant \"create\" on \"serviceaccounts/token\" (resourceNames: [%q]) in namespace %q to the Envoy Gateway ServiceAccount",
			name, namespace)
	}
	return err.Error()
}

// offlineServiceAccountTokenMinter is the minter of the offline reconciler, which has no API
// server to request a token from, so a client assertion from a ServiceAccount cannot be used.
func offlineServiceAccountTokenMinter(context.Context, string, string, []string, int64) (string, time.Time, error) {
	return "", time.Time{}, errors.New("ServiceAccount tokens can only be requested from the Kubernetes API, not in offline mode")
}

// requestServiceAccountToken requests a token for the ServiceAccount with the TokenRequest API.
// It does not read the ServiceAccount, so the only permission it needs is to create
// serviceaccounts/token.
func (r *gatewayAPIReconciler) requestServiceAccountToken(
	ctx context.Context, namespace, name string, audiences []string, expirationSeconds int64,
) (string, time.Time, error) {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &expirationSeconds,
		},
	}
	if err := r.client.SubResource("token").Create(ctx, serviceAccount, tokenRequest); err != nil {
		return "", time.Time{}, err
	}
	return tokenRequest.Status.Token, tokenRequest.Status.ExpirationTimestamp.Time, nil
}

// processServiceAccountToken adds the token for the ServiceAccount of a client assertion to the
// resourceTree, unless it is there already. The ServiceAccount is in the namespace of the policy.
func (r *gatewayAPIReconciler) processServiceAccountToken(
	ctx context.Context, resourceTree *resource.Resources, namespace string, sat *egv1a1.OIDCServiceAccountToken,
) error {
	expirationSeconds, err := resource.ServiceAccountTokenExpirationSeconds(sat)
	if err != nil {
		return err
	}

	key := resource.ServiceAccountTokenKey(namespace, sat.ServiceAccountName, sat.Audiences, expirationSeconds)
	if slices.ContainsFunc(resourceTree.ServiceAccountTokens, func(t *resource.ServiceAccountToken) bool {
		return t.Key() == key
	}) {
		return nil
	}

	resourceTree.ServiceAccountTokens = append(resourceTree.ServiceAccountTokens,
		r.serviceAccountTokens.get(ctx, r.log, namespace, sat.ServiceAccountName, sat.Audiences, expirationSeconds))
	return nil
}
