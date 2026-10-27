// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package kubernetes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/envoygateway"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/logging"
)

type fakeTokenMinter struct {
	now       time.Time
	lifetime  time.Duration
	err       error
	calls     int
	lastAuds  []string
	lastExpry int64
}

func (m *fakeTokenMinter) mint(_ context.Context, _, name string, audiences []string, expirationSeconds int64) (string, time.Time, error) {
	m.calls++
	m.lastAuds = audiences
	m.lastExpry = expirationSeconds
	if m.err != nil {
		return "", time.Time{}, m.err
	}
	return name + "-token-" + string(rune('0'+m.calls)), m.now.Add(m.lifetime), nil
}

type tokenCacheFixture struct {
	cache  *serviceAccountTokenCache
	minter *fakeTokenMinter
	now    time.Time
}

func newTokenCacheFixture() *tokenCacheFixture {
	f := &tokenCacheFixture{
		now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		minter: &fakeTokenMinter{lifetime: time.Hour},
	}
	f.minter.now = f.now
	f.cache = newServiceAccountTokenCache(func() time.Time { return f.now }, f.minter.mint)
	return f
}

func (f *tokenCacheFixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
	f.minter.now = f.now
}

func (f *tokenCacheFixture) get(audiences ...string) *resource.ServiceAccountToken {
	return f.cache.get(context.Background(), logging.DefaultLogger(os.Stdout, egv1a1.LogLevelInfo),
		"default", "oauth2-client", audiences, 3600)
}

func TestServiceAccountTokenCache(t *testing.T) {
	t.Run("first request mints a token", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()

		token := f.get("https://sso.example.com")

		require.Equal(t, 1, f.minter.calls)
		require.Equal(t, []string{"https://sso.example.com"}, f.minter.lastAuds)
		require.Equal(t, int64(3600), f.minter.lastExpry)
		require.Equal(t, "oauth2-client-token-1", token.Token)
		require.Empty(t, token.Error)
		require.Equal(t, "default", token.Namespace)
		require.Equal(t, "oauth2-client", token.Name)
		require.Equal(t, int64(3600), token.ExpirationSeconds)
	})

	t.Run("token is reused until 80 percent of its lifetime has passed", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()
		first := f.get("aud")

		f.advance(47 * time.Minute)
		require.Equal(t, first.Token, f.get("aud").Token)
		require.Equal(t, 1, f.minter.calls)

		f.advance(time.Minute)
		renewed := f.get("aud")
		require.Equal(t, 2, f.minter.calls)
		require.NotEqual(t, first.Token, renewed.Token)
	})

	t.Run("the lifetime that the API server granted decides when to renew", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.minter.lifetime = 10 * time.Minute
		f.cache.begin()
		f.get("aud")

		f.advance(7 * time.Minute)
		f.get("aud")
		require.Equal(t, 1, f.minter.calls)

		f.advance(time.Minute)
		f.get("aud")
		require.Equal(t, 2, f.minter.calls)
	})

	t.Run("audience order does not matter", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()

		first := f.get("b", "a")
		second := f.get("a", "b")

		require.Equal(t, 1, f.minter.calls)
		require.Equal(t, first, second)
		require.Equal(t, []string{"a", "b"}, second.Audiences)
	})

	t.Run("a failed renewal keeps a token that is still valid", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()
		first := f.get("aud")

		f.advance(50 * time.Minute)
		f.minter.err = errors.New("boom")
		kept := f.get("aud")

		require.Equal(t, 2, f.minter.calls)
		require.Equal(t, first.Token, kept.Token)
		require.Empty(t, kept.Error)

		// The renewal is retried soon, not on every reconcile.
		f.get("aud")
		require.Equal(t, 2, f.minter.calls)
		f.advance(serviceAccountTokenRetryInterval)
		f.minter.err = nil
		renewed := f.get("aud")
		require.Equal(t, 3, f.minter.calls)
		require.NotEqual(t, first.Token, renewed.Token)
	})

	t.Run("a failed renewal of an expired token reports the error", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()
		f.get("aud")

		f.advance(2 * time.Hour)
		f.minter.err = errors.New("boom")
		token := f.get("aud")

		require.Empty(t, token.Token)
		require.Equal(t, "boom", token.Error)
	})

	t.Run("a failed request without a cached token reports the error and is retried", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.minter.err = errors.New("boom")
		f.cache.begin()

		token := f.get("aud")
		require.Empty(t, token.Token)
		require.Equal(t, "boom", token.Error)

		f.minter.err = nil
		f.advance(serviceAccountTokenRetryInterval - time.Second)
		require.NotEmpty(t, f.get("aud").Error)
		require.Equal(t, 1, f.minter.calls)

		f.advance(time.Second)
		token = f.get("aud")
		require.Equal(t, 2, f.minter.calls)
		require.NotEmpty(t, token.Token)
		require.Empty(t, token.Error)
	})

	t.Run("forbidden tells the owner which permission to grant", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.minter.err = kerrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts/token"}, "oauth2-client", errors.New("denied"))
		f.cache.begin()

		token := f.get("aud")

		require.Empty(t, token.Token)
		require.Equal(t,
			`forbidden: grant "create" on "serviceaccounts/token" (resourceNames: ["oauth2-client"]) in namespace "default" to the Envoy Gateway ServiceAccount`,
			token.Error)
	})

	t.Run("an already expired token is an error", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.minter.lifetime = -time.Minute
		f.cache.begin()

		token := f.get("aud")

		require.Empty(t, token.Token)
		require.NotEmpty(t, token.Error)
	})

	t.Run("entries that a reconcile did not use are dropped", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()
		f.get("aud")
		f.cache.end()
		require.Len(t, f.cache.entries, 1)

		f.cache.begin()
		require.Zero(t, f.cache.end())
		require.Empty(t, f.cache.entries)
	})

	t.Run("requeue is the earliest renewal among the entries used", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.cache.begin()
		require.Zero(t, f.cache.end())

		f.cache.begin()
		f.get("aud")
		f.minter.lifetime = 20 * time.Minute
		f.get("other")
		require.Equal(t, 16*time.Minute, f.cache.end())

		f.advance(10 * time.Minute)
		f.cache.begin()
		f.get("aud")
		f.get("other")
		require.Equal(t, 6*time.Minute, f.cache.end())
	})

	t.Run("requeue after a failure is the retry interval", func(t *testing.T) {
		f := newTokenCacheFixture()
		f.minter.err = errors.New("boom")
		f.cache.begin()
		f.get("aud")
		require.Equal(t, serviceAccountTokenRetryInterval, f.cache.end())
	})
}

func TestRequestServiceAccountToken(t *testing.T) {
	expiresAt := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	var gotSubResource string
	var gotNamespace, gotName string
	var gotRequest *authenticationv1.TokenRequest
	fakeClient := fakeclient.NewClientBuilder().
		WithScheme(envoygateway.GetScheme()).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceCreate: func(_ context.Context, _ client.Client, subResourceName string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
				gotSubResource = subResourceName
				gotNamespace, gotName = obj.GetNamespace(), obj.GetName()
				gotRequest = subResource.(*authenticationv1.TokenRequest)
				gotRequest.Status.Token = "the-token"
				gotRequest.Status.ExpirationTimestamp.Time = expiresAt
				return nil
			},
		}).
		Build()
	r := &gatewayAPIReconciler{client: fakeClient}

	token, gotExpiry, err := r.requestServiceAccountToken(context.Background(), "default", "oauth2-client", []string{"aud"}, 7200)

	require.NoError(t, err)
	require.Equal(t, "the-token", token)
	require.Equal(t, expiresAt, gotExpiry)
	require.Equal(t, "token", gotSubResource)
	require.Equal(t, "default", gotNamespace)
	require.Equal(t, "oauth2-client", gotName)
	require.Equal(t, []string{"aud"}, gotRequest.Spec.Audiences)
	require.Equal(t, int64(7200), *gotRequest.Spec.ExpirationSeconds)
}

func TestOfflineServiceAccountTokenMinter(t *testing.T) {
	cache := newServiceAccountTokenCache(time.Now, offlineServiceAccountTokenMinter)
	cache.begin()
	token := cache.get(context.Background(), logging.DefaultLogger(os.Stdout, egv1a1.LogLevelInfo),
		"default", "oauth2-client", []string{"aud"}, 3600)
	require.Empty(t, token.Token)
	require.Contains(t, token.Error, "offline mode")
}

func TestProcessServiceAccountToken(t *testing.T) {
	f := newTokenCacheFixture()
	f.cache.begin()
	r := &gatewayAPIReconciler{
		log:                  logging.DefaultLogger(os.Stdout, egv1a1.LogLevelInfo),
		serviceAccountTokens: f.cache,
	}
	tree := resource.NewResources()
	sat := &egv1a1.OIDCServiceAccountToken{
		ServiceAccountName: "oauth2-client",
		Audiences:          []string{"b", "a"},
	}

	require.NoError(t, r.processServiceAccountToken(context.Background(), tree, "default", sat))
	// A second policy with the same ServiceAccount shares the token.
	require.NoError(t, r.processServiceAccountToken(context.Background(), tree, "default", sat))
	// The same ServiceAccount name in another namespace is another token.
	require.NoError(t, r.processServiceAccountToken(context.Background(), tree, "other", sat))
	// A different lifetime is another token.
	sat2 := sat.DeepCopy()
	sat2.Expiration = new(gwapiv1.Duration("2h"))
	require.NoError(t, r.processServiceAccountToken(context.Background(), tree, "default", sat2))

	require.Len(t, tree.ServiceAccountTokens, 3)
	require.Equal(t, 3, f.minter.calls)
	require.Equal(t, int64(3600), tree.ServiceAccountTokens[0].ExpirationSeconds)
	require.Equal(t, int64(7200), tree.ServiceAccountTokens[2].ExpirationSeconds)
	require.Equal(t, []string{"a", "b"}, tree.ServiceAccountTokens[0].Audiences)
}
