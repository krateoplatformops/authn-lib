package basic

import (
	"context"
	"net/http"

	"github.com/krateoplatformops/authn-lib/auth"
	"github.com/krateoplatformops/authn-lib/auth/internal"
	"github.com/krateoplatformops/authn-lib/gcache"
)

// NewCached return new auth.Strategy.
// The returned strategy, caches the invocation result of authenticate function.
func NewCached(f AuthenticateFunc, cache gcache.Cache, opts ...auth.Option) auth.Strategy {
	cb := new(cachedBasic)
	cb.fn = f
	cb.cache = cache
	cb.comparator = plainText{}
	cb.hasher = internal.PlainTextHasher{}
	for _, opt := range opts {
		opt.Apply(cb)
	}
	return New(cb.authenticate, opts...)
}

type entry struct {
	password string
	info     auth.Info
}

type cachedBasic struct {
	fn         AuthenticateFunc
	comparator Comparator
	cache      gcache.Cache
	hasher     internal.Hasher
}

func (c *cachedBasic) authenticate(ctx context.Context, r *http.Request, userName, pass string) (auth.Info, error) { // nolint:lll
	hash := c.hasher.Hash(userName)
	v, err := c.cache.Get(hash)
	// if info not found invoke user authenticate function
	if err != nil {
		return c.authenticatAndHash(ctx, r, hash, userName, pass)
	}

	ent, ok := v.(entry)
	if !ok {
		return nil, auth.NewTypeError("strategies/basic:", entry{}, v)
	}

	return ent.info, c.comparator.Compare(ent.password, pass)
}

func (c *cachedBasic) authenticatAndHash(ctx context.Context, r *http.Request, hash string, userName, pass string) (auth.Info, error) { //nolint:lll
	info, err := c.fn(ctx, r, userName, pass)
	if err != nil {
		return nil, err
	}

	hashedPass, _ := c.comparator.Hash(pass)
	ent := entry{
		password: hashedPass,
		info:     info,
	}
	c.cache.Set(hash, ent)

	return info, nil
}
