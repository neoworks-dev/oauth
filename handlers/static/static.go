// Package static serves the shared, self-hosted assets for the standalone auth
// pages: the design-system stylesheet, its theme script, the fonts and the mascot images. Self-hosted (not
// CDN) for the same reason as the other auth assets — these pages handle
// passwords and Account Master Keys, so nothing is loaded cross-origin.
package static

import (
	"embed"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed assets/*
var assets embed.FS

// Handler serves the shared CSS and font files under /auth/static.
type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/static/neoworks.css", h.serve("assets/neoworks.css", "text/css; charset=utf-8"))
	r.Get("/static/theme.js", h.serve("assets/theme.js", "text/javascript; charset=utf-8"))
	r.Get("/static/icon.svg", h.serve("assets/icon.svg", "image/svg+xml"))
	r.Get("/static/geist-400.woff2", h.serve("assets/geist-400.woff2", "font/woff2"))
	r.Get("/static/geist-500.woff2", h.serve("assets/geist-500.woff2", "font/woff2"))
	r.Get("/static/geist-600.woff2", h.serve("assets/geist-600.woff2", "font/woff2"))
	r.Get("/static/caveat-500.woff2", h.serve("assets/caveat-500.woff2", "font/woff2"))
	r.Get("/static/marmot/{name}", h.serveMarmot)
}

// serveMarmot serves one mascot illustration. The name is matched against the
// embedded files, so it cannot reach outside assets/marmot.
func (h *Handler) serveMarmot(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	data, err := assets.ReadFile("assets/marmot/" + path.Base(name))
	if err != nil || !strings.HasSuffix(name, ".webp") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

func (h *Handler) serve(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := assets.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		// Fonts are immutable; the stylesheet may change between deploys, so let
		// it revalidate rather than caching forever.
		if strings.HasSuffix(path, ".woff2") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		_, _ = w.Write(data)
	}
}
