package handler

import(
	"github.com/rs/zerolog/log"
	"encoding/json"
	"net/http"
	"io/ioutil"
	"fmt"
	"encoding/base64"
	//"bytes"

	"github.com/go-card-crypto/internal/erro"
	"github.com/go-card-crypto/internal/core"
	"github.com/go-card-crypto/internal/service"
)

var (
	childLogger = log.With().Str("handler", "handler").Logger()
)
const MAX_UPLOAD_SIZE = 512 * 1024

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

func (h *HttpWorkerAdapter) AddRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("AddRSAKey")
	
	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	fileName := req.FormValue("file_name")
	tenantId := req.FormValue("tenant_id")
	hostId 	:= req.FormValue("host_id")
	typeKey := req.FormValue("type_key")

	file, file_handler, err := req.FormFile("file")
    if err != nil {
        json.NewEncoder(rw).Encode(erro.ErrFile)
		return
    }
    defer file.Close()

	if file_handler.Size <= 0 {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}
	
	// Check mimetype
	/*buff := make([]byte, 512)
	_, err = file.Read(buff)
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrStatusInternalServerError)
		return
	}
	filetype := http.DetectContentType(buff)
	if filetype != "text/plain; charset=utf-8" {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}*/

	// Save file
	/*tempFile, err := ioutil.TempFile("./", fileName)
    if err != nil {
        fmt.Println(err)
    }
    defer tempFile.Close()*/

	fileBytes, err := ioutil.ReadAll(file)
    if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
    }

	//tempFile.Write(fileBytes) // Save file

	fileB64 := base64.StdEncoding.EncodeToString(fileBytes)
	fmt.Println("fileB64: " + fileB64)

	rsa_key := core.NewRSAKey(
		core.WithFileName(fileName),
		core.WithTenantId(tenantId),
		core.WithHostId(hostId),
		core.WithTypeKey(typeKey),
		core.WithStatus("ACTIVE"),
		core.WithRSAPublicKey(fileB64),
		core.WithRSAPublicKeyBytes(fileBytes),
	)

	res, err := h.workerService.AddRSAKey(*rsa_key)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) GetRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("GetRSAKey")
	
	tenantId := req.FormValue("tenant_id")
	hostId := req.FormValue("host_id")
	status := "ACTIVE"

	rsa_key := core.NewRSAKey(
		core.WithTenantId(tenantId),
		core.WithHostId(hostId),
		core.WithStatus(status),
	)

	res, err := h.workerService.GetRSAKey(*rsa_key)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) CheckSignatureRSA(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("CheckSignatureRSA")

	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	rsaIdVerifyKey := req.FormValue("rsa_id_verify_key")

	// download file signed
	file_sig, file_handler_sig, err := req.FormFile("file_sig")
    if err != nil {
        json.NewEncoder(rw).Encode(erro.ErrFile)
		return
    }
    defer file_sig.Close()

	if file_handler_sig.Size <= 0 {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}
	
	fileBytesSig, err := ioutil.ReadAll(file_sig)
    if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
    }

	// download file encrypt
	file_enc, file_handler_enc, err := req.FormFile("file_enc")
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFile)
		return
	}
	defer file_enc.Close()
	
	if file_handler_enc.Size <= 0 {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}
		
	fileBytesEnc, err := ioutil.ReadAll(file_enc)
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}

	//fileSigned	  := core.FileEncrypted{RSAHosttKeyName: rsaIdVerifyKey, FileData: bytes.NewBuffer(fileBytesSig).String()}
	//fileEncrypted := core.FileEncrypted{RSAHosttKeyName: rsaIdVerifyKey, FileData: bytes.NewBuffer(fileBytesEnc).String()}

	res, err := h.workerService.CheckSignatureRSA(rsaIdVerifyKey, fileBytesSig, fileBytesEnc)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return

}