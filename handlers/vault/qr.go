package vault

import (
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	qrPixels      = 320
	maxQRTextSize = 1500
)

// handleQR renders a QR code for the text in ?p. It only carries public
// handover data (session id, ephemeral public key, origin), never key material.
func (server *Server) handleQR(response http.ResponseWriter, request *http.Request) {
	text := request.URL.Query().Get("p")
	if text == "" || len(text) > maxQRTextSize {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	image, err := qrcode.Encode(text, qrcode.Medium, qrPixels)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "server_error")
		return
	}
	response.Header().Set("Content-Type", "image/png")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = response.Write(image)
}
