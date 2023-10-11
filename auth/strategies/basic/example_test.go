package basic_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/krateoplatformops/authn-lib/auth"
	"github.com/krateoplatformops/authn-lib/auth/strategies/basic"
)

func Example() {
	strategy := basic.New(exampleAuthFunc)

	// user request
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "test")
	user, err := strategy.Authenticate(req.Context(), req)
	fmt.Println(user.GetID(), err)

	req.SetBasicAuth("test", "1234")
	_, err = strategy.Authenticate(req.Context(), req)
	fmt.Println(err)

	// Output:
	// 10 <nil>
	// Invalid credentials
}

func exampleAuthFunc(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "test" && password == "test" {
		return auth.NewDefaultUser("test", "10", nil, nil), nil
	}

	return nil, fmt.Errorf("Invalid credentials")
}
