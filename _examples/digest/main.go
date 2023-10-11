package main

import (
	_ "crypto/md5"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/krateoplatformops/authn-lib/auth"
	"github.com/krateoplatformops/authn-lib/auth/strategies/digest"
	"github.com/krateoplatformops/authn-lib/gcache"
)

// Usage:
// curl --digest --user admin:admin http://127.0.0.1:8080/v1/book/1449311601

var strategy *digest.Digest

func init() {
	var c gcache.Cache
	c = gcache.New(10).Simple().Build()
	c.SetTTL(time.Minute * 3)
	strategy = digest.New(validateUser, c)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/v1/book/{id}", middleware(http.HandlerFunc(getBookAuthor))).Methods("GET")
	log.Println("server started and listening on http://127.0.0.1:8080")
	http.ListenAndServe("127.0.0.1:8080", router)
}

func getBookAuthor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	books := map[string]string{
		"1449311601": "Ryan Boyd",
		"148425094X": "Yvonne Wilson",
		"1484220498": "Prabath Siriwarden",
	}
	body := fmt.Sprintf("Author: %s \n", books[id])
	w.Write([]byte(body))
}

func validateUser(userName string) (string, auth.Info, error) {
	// here connect to db or any other service to fetch user and validate it.
	if userName == "admin" {
		return "admin", auth.NewDefaultUser("admin", "1", nil, nil), nil
	}

	return "", nil, fmt.Errorf("Invalid credentials")
}

func middleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing Auth Middleware")
		user, err := strategy.Authenticate(r.Context(), r)
		if err != nil {
			code := http.StatusUnauthorized
			w.Header().Add("WWW-Authenticate", strategy.GetChallenge())
			http.Error(w, http.StatusText(code), code)
			fmt.Println("send error", err)
			return
		}
		log.Printf("User %s Authenticated\n", user.GetUserName())
		next.ServeHTTP(w, r)
	})
}
