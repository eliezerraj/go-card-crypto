package service


import (
	"crypto/aes"
	"crypto/cipher"
    "crypto/rand"
	"fmt"
	b64 "encoding/base64"
	//"io"
	//"io/ioutil"

	"github.com/rs/zerolog/log"

	"github.com/go-card-crypto/internal/core"
//	"github.com/go-card-crypto/internal/erro"
	"github.com/go-card-crypto/internal/repository/db_postgre"

)

var childLogger = log.With().Str("service", "service").Logger()

type WorkerService struct {
	workerRepository 		*db_postgre.WorkerRepository
}

func NewWorkerService(workerRepository *db_postgre.WorkerRepository) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		workerRepository: workerRepository,
	}
}
//----------------------------------------

// Save the Tenant RSA Public Key
func (w WorkerService) AddRSAKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("AddRSAKey")

	res, err := w.workerRepository.AddRSAKey(rsaKey)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// Save the Host RSA Public Key
func (w WorkerService) GetRSAKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("GetRSAKey")

	res, err := w.workerRepository.GetRSAKey(rsaKey)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// Check signature
func (w WorkerService) CheckSignatureRSA(rsaIdVerifyKey string, fileEnd []byte, fileSig []byte) (bool, error){
	childLogger.Debug().Msg("CheckSignatureRSA")

//var AES_KEY = "a43385c05718c76db8a0b9a9d2682bd2d89932e75aa5fe8a75f3f47d78a934a7"
//	var AES_IV  = "3d5d06c1414d977790be8ac0bb373dab"
 
/*	rsaPub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		log.Error().Err(erro.ErrRSAPubKeyInvalid).Msg("ERRO FATAL CreateAESKey")
		return false, erro.ErrRSAPubKeyInvalid
	}
*/

	return true, nil
}

///
func (w WorkerService) CreateAESKey(keyPhrase string) ([]byte, error){
	childLogger.Debug().Msg("CreateAESKey")

	aesBlock, err := aes.NewCipher([]byte(keyPhrase))
	if err != nil {
		log.Error().Err(err).Msg("ERRO FATAL CreateAESKey")
		return nil, err
	}

	fmt.Println(aesBlock)

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Error().Err(err).Msg("ERRO FATAL CreateAESKey")
		return nil, err
	}

	nonce := make([]byte, gcmInstance.NonceSize())
    _, err = rand.Read(nonce)
    if err != nil {
		log.Error().Err(err).Msg("ERRO FATAL CreateAESKey")
		return nil, err
    }

	// Writing ciphertext file
	plainText := "meu segredo 123"
	cipherText := gcmInstance.Seal(nonce, nonce, []byte(plainText), nil)

	/*err = ioutil.WriteFile("./pubkey.bin", cipherText, 0777)
	if err != nil {
		log.Error().Err(err).Msg("ERRO FATAL CreateAESKey")
		return nil, err
	}*/

	blobString := b64.StdEncoding.EncodeToString(cipherText)
	fmt.Println(blobString)

	return cipherText, nil
}