// Package static serves the shared, self-hosted assets for the standalone auth
// pages: the design-system stylesheet and the Geist web font. Self-hosted (not
// CDN) for the same reason as the other auth assets — these pages handle
// passwords and Account Master Keys, so nothing is loaded cross-origin.
package static

import (
	"embed"
	"net/http"
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
	r.Get("/auth/static/neoworks.css", h.serve("assets/neoworks.css", "text/css; charset=utf-8"))
	r.Get("/auth/static/icon.svg", h.serve("assets/icon.svg", "image/svg+xml"))
	r.Get("/auth/static/geist-400.woff2", h.serve("assets/geist-400.woff2", "font/woff2"))
	r.Get("/auth/static/geist-500.woff2", h.serve("assets/geist-500.woff2", "font/woff2"))
	r.Get("/auth/static/geist-600.woff2", h.serve("assets/geist-600.woff2", "font/woff2"))
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
