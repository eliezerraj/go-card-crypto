package handler

import(
	"github.com/rs/zerolog/log"
	"encoding/json"
	"net/http"
	"github.com/go-card-crypto/internal/service"
)

var childLogger = log.With().Str("handler", "handler").Logger()

type HttpWorkerAdapter struct {
	workerService 	*service.WorkerService
}

func NewHttpWorkerAdapter(workerService *service.WorkerService) *HttpWorkerAdapter {
	childLogger.Debug().Msg("NewHttpWorkerAdapter")
	return &HttpWorkerAdapter{
		workerService: workerService,
	}
}

func (h *HttpWorkerAdapter) Health(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("Health")

	health := true
	json.NewEncoder(rw).Encode(health)
	return
}

func (h *HttpWorkerAdapter) AddPublicKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("AddPublicKey")

	health := "AddPublicKey"
	json.NewEncoder(rw).Encode(health)
	return
}