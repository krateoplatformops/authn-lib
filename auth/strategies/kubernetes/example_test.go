package kubernetes

import (
	"fmt"
	"net/http"

	"github.com/krateoplatformops/authn-lib/auth/strategies/token"
	"github.com/krateoplatformops/authn-lib/gcache"
)

func ExampleNew() {
	cache := gcache.New(0).Simple().Build()
	kube := New(cache)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}

func ExampleGetAuthenticateFunc() {
	cache := gcache.New(0).Simple().Build()
	fn := GetAuthenticateFunc()
	kube := token.New(fn, cache)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}

func Example() {
	st := SetServiceAccountToken("Service Account Token")
	cache := gcache.New(0).Simple().Build()
	kube := New(cache, st)
	r, _ := http.NewRequest("", "/", nil)
	_, err := kube.Authenticate(r.Context(), r)
	fmt.Println(err != nil)
	// Output:
	// true
}
