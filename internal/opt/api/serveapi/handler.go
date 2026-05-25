package serveapi

import (
	"io"
	"net/http"
	"strconv"

	"github.com/pgrwl/pgrwl/internal/opt/shared/x/httpx"
)

type Handler struct {
	Service Service
}

func NewHandler(s Service) *Handler {
	return &Handler{
		Service: s,
	}
}

func (c *Handler) WalFileDownloadHandler(w http.ResponseWriter, r *http.Request) {
	filename, err := httpx.PathValueString(r, "filename")
	if err != nil {
		http.Error(w, "expect filename path-param", http.StatusBadRequest)
		return
	}

	file, err := c.Service.GetWalFile(r.Context(), filename)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// TODO: send checksum in headers

	// Buffer the entire file before sending any response bytes.
	// This ensures that if the S3 download is interrupted mid-stream
	// (e.g. by a proxy), we can return a proper 500 error instead of
	// silently delivering a truncated WAL segment (which Postgres would
	// accept as a success and then fail with "wrong size").
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "cannot read file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, err = w.Write(data)
	if err != nil {
		http.Error(w, "cannot write file-data to response", http.StatusInternalServerError)
		return
	}
}
