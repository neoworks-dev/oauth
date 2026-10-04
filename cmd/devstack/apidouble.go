package main

import (
	"net/http"
	"regexp"
)

var grantPath = regexp.MustCompile(`^/api/v1/nodes/[^/]+/grants$`)

// withAPIDouble answers the one data API call the vault makes in browser tests,
// appending a signed grant to a node's access log, because the devstack runs
// without the api service. Real log handling is covered by the live-stack smoke
// run, which includes the api.
func withAPIDouble(next http.Handler, vaultOrigin string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodOptions && grantPath.MatchString(request.URL.Path) {
			allowVault(response, vaultOrigin)
			response.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method == http.MethodPost && grantPath.MatchString(request.URL.Path) {
			allowVault(response, vaultOrigin)
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte("{}"))
			return
		}
		next.ServeHTTP(response, request)
	})
}

func allowVault(response http.ResponseWriter, vaultOrigin string) {
	response.Header().Set("Access-Control-Allow-Origin", vaultOrigin)
	response.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	response.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
}
