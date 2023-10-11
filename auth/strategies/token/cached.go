package token

import (
	"context"
	"net/http"
	"time"

	"github.com/krateoplatformops/authn-lib/auth"
	"github.com/krateoplatformops/authn-lib/gcache"
)

// AuthenticateFunc declare function signature to authenticate request using token.
// Any function that has the appropriate signature can be registered to the token strategy.
// AuthenticateFunc must return authenticated user info and token expiry time, otherwise error.
type AuthenticateFunc func(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error)

// NoOpAuthenticate implements AuthenticateFunc, it return nil, time.Time{}, ErrNOOP,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
func NoOpAuthenticate(ctx context.Context, r *http.Request, token string) (auth.Info, time.Time, error) {
	return nil, time.Time{}, ErrNOOP
}

// New return new token strategy that caches the invocation result of authenticate function.
func New(fn AuthenticateFunc, ac gcache.Cache, opts ...auth.Option) auth.Strategy {
	c := new(cachedToken)
	c.cache = ac
	c.fn = fn
	return newCore(c, opts...)
}

type cachedToken struct {
	cache gcache.Cache
	fn    AuthenticateFunc
}

func (c *cachedToken) authenticate(ctx context.Context, r *http.Request, hash, token string) (auth.Info, error) {
	if v, err := c.cache.Get(hash); err == nil {
		info, ok := v.(auth.Info)
		if !ok {
			return nil, auth.NewTypeError("strategies/token:", (*auth.Info)(nil), v)
		}
		return info, nil
	}

	// token not found invoke user authenticate function
	info, t, err := c.fn(ctx, r, token)
	if err != nil {
		return nil, err
	}

	c.cache.SetWithExpire(hash, info, time.Until(t))
	return info, nil
}

func (c *cachedToken) append(token string, info auth.Info) error {
	c.cache.Set(token, info)
	return nil
}

func (c *cachedToken) revoke(token string) error {
	c.cache.Remove(token)
	return nil
}
