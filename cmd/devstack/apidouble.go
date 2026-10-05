package main

import (
	"net/http"
	"regexp"
)

var grantPath = regexp.MustCompile(`^/api/v1/nodes/[^/]+/grants$`)

const contactCodePath = "/api/v1/contact-code"

// doubleContactCode is the code the double reports for every account.
const doubleContactCode = "7K3M-9QX2-H4TA"

// withAPIDouble answers the data API calls the vault makes in browser tests,
// because the devstack runs without the api service: appending a signed grant
// to a node's access log and reading the account's contact code. Real handling
// is covered by the live-stack smoke run, which includes the api.
func withAPIDouble(next http.Handler, vaultOrigin string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		isDoubled := grantPath.MatchString(request.URL.Path) || request.URL.Path == contactCodePath
		if !isDoubled {
			next.ServeHTTP(response, request)
			return
		}
		allowVault(response, vaultOrigin)
		if request.Method == http.MethodOptions {
			response.WriteHeader(http.StatusNoContent)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == contactCodePath {
			_, _ = response.Write([]byte(`{"code":"` + doubleContactCode + `"}`))
			return
		}
		if request.Method == http.MethodPost && grantPath.MatchString(request.URL.Path) {
			_, _ = response.Write([]byte("{}"))
			return
		}
		next.ServeHTTP(response, request)
	})
}

func allowVault(response http.ResponseWriter, vaultOrigin string) {
	response.Header().Set("Access-Control-Allow-Origin", vaultOrigin)
	response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	response.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}
