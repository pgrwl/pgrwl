package receiveapi

import (
	"io"
	"net/http"

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

func (c *Handler) StatusHandler(w http.ResponseWriter, _ *http.Request) {
	status := c.Service.Status()
	httpx.WriteJSON(w, http.StatusOK, status)
}

func (c *Handler) BriefConfig(w http.ResponseWriter, r *http.Request) {
	briefConfig, err := c.Service.BriefConfig(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, err)
	}
	httpx.WriteJSON(w, http.StatusOK, briefConfig)
}

func (c *Handler) FullRedactedConfig(w http.ResponseWriter, r *http.Request) {
	briefConfig := c.Service.FullRedactedConfig(r.Context())
	httpx.WriteJSON(w, http.StatusOK, briefConfig)
}

func (c *Handler) WalsHandler(w http.ResponseWriter, r *http.Request) {
	snap, err := c.Service.ListWALFiles(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"err": err.Error(),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, snap)
}

func (c *Handler) BackupsHandler(w http.ResponseWriter, r *http.Request) {
	snap, err := c.Service.ListBackups(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"err": err.Error(),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, snap)
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

	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "cannot read file", http.StatusInternalServerError)
		return
	}
}

func (c *Handler) StopReceiverHandler(w http.ResponseWriter, _ *http.Request) {
	c.Service.StopReceiver()
	w.WriteHeader(http.StatusOK)
}

func (c *Handler) StartReceiverHandler(w http.ResponseWriter, r *http.Request) {
	if err := c.Service.StartReceiver(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}
