package handler

import(
	"github.com/rs/zerolog/log"
	"encoding/json"
	"net/http"
	"io/ioutil"
	"fmt"
	"encoding/base64"

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
	typeKey := req.FormValue("type_key")
	status := "ACTIVE"

	rsa_key := core.NewRSAKey(
		core.WithTenantId(tenantId),
		core.WithHostId(hostId),
		core.WithTypeKey(typeKey),
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

func (h *HttpWorkerAdapter) EncryptDataWithRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("EncryptDataWithRSAKey")

	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	rsaIdPublicKey 	:= req.FormValue("rsa_id_public_key")
	msg_encrypt 	:= req.FormValue("msg_encrypt")

	fmt.Println("msg_encrypt : ",msg_encrypt)

	var fileBytesToEncrypt []byte
	if (msg_encrypt != ""){
		fileBytesToEncrypt = []byte(msg_encrypt)
	}else{
		// download file encrypt
		file_encrypt, file_handler_encrypt, err := req.FormFile("file_encrypt")
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFile)
			return
		}
		defer file_encrypt.Close()

		if file_handler_encrypt.Size <= 0 {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
		fileBytesToEncrypt, err = ioutil.ReadAll(file_encrypt)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
	}

	res, err := h.workerService.EncryptDataWithRSAKey(rsaIdPublicKey, fileBytesToEncrypt)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) DecryptDataWithRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("DecryptDataWithRSAKey")

	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	rsaIdPrivateKey := req.FormValue("rsa_id_private_key")
	file_encrypt_b64 := req.FormValue("file_encrypt_b64")

	var fileBytesToDecrypt []byte
	if (file_encrypt_b64 != ""){
		fileBytesToDecrypt, err = base64.StdEncoding.DecodeString(file_encrypt_b64)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
	}else{
		// download file encrypt
		file_decrypt, file_handler_decrypt, err := req.FormFile("file_decrypt")
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFile)
			return
		}
		defer file_decrypt.Close()

		if file_handler_decrypt.Size <= 0 {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
		fileBytesToDecrypt, err = ioutil.ReadAll(file_decrypt)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
	}

	res, err := h.workerService.DecryptDataWithRSAKey(rsaIdPrivateKey, fileBytesToDecrypt)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) SignDataWithRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("SignDataWithRSAKey")

	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	rsaIdPrivateKey := req.FormValue("rsa_id_private_key")
	msg_to_sign 	:= req.FormValue("msg_to_sign")

	var fileBytesToSign []byte
	if(msg_to_sign != ""){
		fileBytesToSign = []byte(msg_to_sign)
	}else{
		// download file encrypt
		file_to_sign, file_handler_sign, err := req.FormFile("file_to_sign")
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFile)
			return
		}
		defer file_to_sign.Close()

		if file_handler_sign.Size <= 0 {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}

		fileBytesToSign, err = ioutil.ReadAll(file_to_sign)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
	}

	res, err := h.workerService.SignDataWithRSAKey(rsaIdPrivateKey, fileBytesToSign)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return
}

func (h *HttpWorkerAdapter) VerifySignedDataWithRSAKey(rw http.ResponseWriter, req *http.Request) {
	childLogger.Debug().Msg("VerifySignedDataWithRSAKey")

	err := req.ParseMultipartForm(MAX_UPLOAD_SIZE) //10 MB
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileSize)
		return
	}

	rsaIdPublicKey := req.FormValue("rsa_id_public_key")
	msg_to_verify := req.FormValue("msg_to_verify")
	msg_signature := req.FormValue("msg_signature")

	var fileBytesToVerify []byte
	var fileBytesSignature []byte

	if (msg_to_verify != ""){
		fileBytesToVerify = []byte(msg_to_verify)

		fileBytesSignature, err = base64.StdEncoding.DecodeString(msg_signature) 
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrDecode)
			return
		}
	}else{
		// download file verify
		file_to_verify, file_handler_verify, err := req.FormFile("file_to_verify")
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFile)
			return
		}
		defer file_to_verify.Close()
		
		if file_handler_verify.Size <= 0 {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}

		fileBytesToVerify, err = ioutil.ReadAll(file_to_verify)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}

		file_signature, file_handler_signature, err := req.FormFile("file_signature")
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFile)
			return
		}
		defer file_signature.Close()
	
		if file_handler_signature.Size <= 0 {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
		
		fileBytesSignature, err = ioutil.ReadAll(file_signature)
		if err != nil {
			json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
			return
		}
	}

	res, err := h.workerService.VerifySignedDataWithRSAKey(rsaIdPublicKey, fileBytesToVerify, fileBytesSignature)
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
	file_signature, file_handler_signature, err := req.FormFile("file_signature")
    if err != nil {
        json.NewEncoder(rw).Encode(erro.ErrFile)
		return
    }
    defer file_signature.Close()

	if file_handler_signature.Size <= 0 {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}
	
	fileBytesSignature, err := ioutil.ReadAll(file_signature)
    if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
    }

	// download file encrypt
	file_encrypt, file_handler_encrypt, err := req.FormFile("file_encrypt")
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFile)
		return
	}
	defer file_encrypt.Close()
	
	if file_handler_encrypt.Size <= 0 {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}
		
	fileBytesEncrypt, err := ioutil.ReadAll(file_encrypt)
	if err != nil {
		json.NewEncoder(rw).Encode(erro.ErrFileInvalid)
		return
	}

	res, err := h.workerService.CheckSignatureRSA(rsaIdVerifyKey, fileBytesEncrypt, fileBytesSignature)
	if err != nil {
		json.NewEncoder(rw).Encode(err.Error())
		return
	}

	json.NewEncoder(rw).Encode(res)
	return

}