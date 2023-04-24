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
	//"github.com/go-card-crypto/internal/erro"
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

func (w WorkerService) GetRSAKey() (error){
	childLogger.Debug().Msg("GetRSAKey")

	return nil
}

func (w WorkerService) AddTenantPublicKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("AddTenantPublicKey")

	res, err := w.workerRepository.AddTenantPublicKey(rsaKey)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (w WorkerService) GetPublicKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("AddPublicKey")

	res, err := w.workerRepository.AddPublicKey(rsaKey)
	if err != nil {
		return nil, err
	}

	return res, nil
}