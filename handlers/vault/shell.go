package vault

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/handlers/static"
)

//go:embed templates/app.html
var appTemplateSource string
var appTemplate = template.Must(template.New("app").Parse(appTemplateSource))

//go:embed static
var vaultAssets embed.FS

// pagePaths are the single-page app's routes; the browser-side router renders
// the matching view.
var pagePaths = []string{"/", "/signin", "/signup", "/recover", "/recover/cancel", "/account", "/handover"}

// bootData is handed to the page as a JSON attribute. It carries no secrets.
type bootData struct {
	VaultOrigin     string `json:"vaultOrigin"`
	APIURL          string `json:"apiUrl"`
	Debug           bool   `json:"debug"`
	EscrowAvailable bool   `json:"escrowAvailable"`
}

func (server *Server) registerPages(router chi.Router) {
	for _, pagePath := range pagePaths {
		router.Get(pagePath, server.servePage)
	}
	router.Get("/static/vault/*", serveVaultAsset)
	static.NewHandler().Register(router)
}

func (server *Server) servePage(response http.ResponseWriter, request *http.Request) {
	encoded, err := json.Marshal(bootData{
		VaultOrigin:     originOf(server.config.VaultURL),
		APIURL:          server.config.APIURL,
		Debug:           server.config.Debug,
		EscrowAvailable: server.escrow.Available(),
	})
	if err != nil {
		http.Error(response, "render error", http.StatusInternalServerError)
		return
	}
	var page bytes.Buffer
	if err := appTemplate.Execute(&page, map[string]string{"Boot": string(encoded)}); err != nil {
		http.Error(response, "render error", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = page.WriteTo(response)
}

func serveVaultAsset(response http.ResponseWriter, request *http.Request) {
	name := path.Base(request.URL.Path)
	content, err := vaultAssets.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	response.Header().Set("Content-Type", assetContentType(name))
	response.Header().Set("Cache-Control", assetCacheControl(name))
	_, _ = response.Write(content)
}

func assetContentType(name string) string {
	if strings.HasSuffix(name, ".css") {
		return "text/css; charset=utf-8"
	}
	return "text/javascript; charset=utf-8"
}

// assetCacheControl lets the unchanging libsodium builds be cached for a year
// and makes every other asset revalidate.
func assetCacheControl(name string) string {
	if strings.HasPrefix(name, "libsodium") {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}
