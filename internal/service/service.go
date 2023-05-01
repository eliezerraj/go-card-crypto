package service


import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
    "crypto/rand"
	"crypto/rsa"
//	"crypto/sha512"
	"crypto/sha256"
	"fmt"
    "crypto/x509"
    "encoding/pem"
	"encoding/base64"
	"io/ioutil"

	"github.com/rs/zerolog/log"

	"github.com/go-card-crypto/internal/core"
	"github.com/go-card-crypto/internal/erro"
	"github.com/go-card-crypto/internal/repository/db_postgre"

)

var childLogger = log.With().Str("service", "service").Logger()

type WorkerService struct {
	workerRepository 		*db_postgre.WorkerRepository
}

func ParseRsaPublicKeyFromPemStr(pubPEM []byte) (*rsa.PublicKey, error) {
	childLogger.Debug().Msg("ParseRsaPublicKeyFromPemStr")

	fmt.Printf("%s/n",pubPEM)

	block, _ := pem.Decode(pubPEM)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		fmt.Println("err ", err)
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		fmt.Println("err ", err)
		return nil, err
	}
	return key, nil
}

func ParseRsaPrivateKeyFromPemStr(privPEM []byte) (*rsa.PrivateKey, error) {
	childLogger.Debug().Msg("ParseRsaPrivateKeyFromPemStr")

	fmt.Printf("%s/n",privPEM)

	block, _ := pem.Decode(privPEM)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, erro.ErrRSAInvalidKey
	}
	return key, nil
}

func NewWorkerService(workerRepository *db_postgre.WorkerRepository) *WorkerService{
	childLogger.Debug().Msg("NewWorkerService")

	return &WorkerService{
		workerRepository: workerRepository,
	}
}

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

// EncryptData with RSA pub Key
func (w WorkerService) EncryptDataWithRSAKey(rsaIdPublicKey string, fileBytesToEncrypt []byte) (*core.FileData, error){
	childLogger.Debug().Msg("EncryptDataWithRSAKey")

	status := "ACTIVE" 
	typeKey := "rsa_public" 

	// Retrieve RDS pub-key
	rsa_key := core.NewRSAKey(
		core.WithTenantId(rsaIdPublicKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdPublicKey),
		core.WithStatus(status),
	)
	
	res, err := w.workerRepository.GetRSAKey(*rsa_key)
	if err != nil {
		childLogger.Error().Err(err).Msg("GetRSAKey")
		return nil, err
	}
	
	pubPem, err := base64.StdEncoding.DecodeString(res.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return nil, err
	}
	// to validate the RDA pub Key
	publicKey, err := ParseRsaPublicKeyFromPemStr(pubPem)
	if err != nil {
		childLogger.Error().Err(err).Msg("ParseRsaPublicKeyFromPemStr")
		return nil, err
	}

	encryptedBytes, err := rsa.EncryptOAEP(	sha256.New(),
											rand.Reader,
											publicKey,
											fileBytesToEncrypt,
											nil)
	if err != nil {
		childLogger.Error().Err(err).Msg("EncryptOAEP")
		return nil, err
	}

	ioutil.WriteFile("../keys/client.msg.enc", []byte(encryptedBytes), 777)
	
	result := core.FileData{
		FileBytes: encryptedBytes,
		FileBytesB64: base64.StdEncoding.EncodeToString(encryptedBytes),
	}

	return &result, nil
}

// DecryptData with RSA private Key
func (w WorkerService) DecryptDataWithRSAKey(rsaIdPrivateKey string, fileBytesToDecrypt []byte) (*core.FileData, error){
	childLogger.Debug().Msg("DecryptDataWithRSAKey")

	status := "ACTIVE" 
	typeKey := "rsa_private" 

	rsa_key_p := core.NewRSAKey(
		core.WithTenantId(rsaIdPrivateKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdPrivateKey),
		core.WithStatus(status),
	)
	resp, err := w.workerRepository.GetRSAKey(*rsa_key_p)
	if err != nil {
		return nil, err
	}
	privPem, err := base64.StdEncoding.DecodeString(resp.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return nil, err
	}
	// to validate the RDA priv Key
	privateKey, err :=ParseRsaPrivateKeyFromPemStr(privPem)
	if err != nil {
		return nil, err
	}

	decryptedBytes, err := privateKey.Decrypt(	nil, 
												fileBytesToDecrypt,
												&rsa.OAEPOptions{Hash: crypto.SHA256})

	result := core.FileData{ MsgOriginal: string(decryptedBytes) }
	return &result, nil
}

// Sign a data
func (w WorkerService) SignDataWithRSAKey(rsaIdPrivateKey string, fileBytesToSign []byte) (*core.FileData, error){
	childLogger.Debug().Msg("SignDataWithRSAKey")

	status := "ACTIVE" 
	typeKey := "rsa_private" 

	rsa_key_p := core.NewRSAKey(
		core.WithTenantId(rsaIdPrivateKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdPrivateKey),
		core.WithStatus(status),
	)
	resp, err := w.workerRepository.GetRSAKey(*rsa_key_p)
	if err != nil {
		return nil, err
	}
	privPem, err := base64.StdEncoding.DecodeString(resp.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return nil, err
	}
	// to validate the RDA priv Key
	privateKey, err :=ParseRsaPrivateKeyFromPemStr(privPem)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(fileBytesToSign) 

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, err
	}

	ioutil.WriteFile("../keys/client.msg.sig", []byte(signature), 777)

	result := core.FileData{
		MsgOriginal: string(fileBytesToSign[:]),
		FileBytesB64: base64.StdEncoding.EncodeToString(signature),
	}

	return &result, nil
}

// Verify data signture 
func (w WorkerService) VerifySignedDataWithRSAKey(rsaIdPublicKey string, fileBytesToVerify []byte, fileBytesSignature []byte) (bool, error){
	childLogger.Debug().Msg("VerifySignedDataWithRSAKey")

	status := "ACTIVE" 
	typeKey := "rsa_public" 

	// Retrieve RDS pub-key
	rsa_key := core.NewRSAKey(
		core.WithTenantId(rsaIdPublicKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdPublicKey),
		core.WithStatus(status),
	)
	
	res, err := w.workerRepository.GetRSAKey(*rsa_key)
	if err != nil {
		childLogger.Error().Err(err).Msg("GetRSAKey")
		return false, err
	}
	
	pubPem, err := base64.StdEncoding.DecodeString(res.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return false, err
	}
	// to validate the RDA pub Key
	publicKey, err := ParseRsaPublicKeyFromPemStr(pubPem)
	if err != nil {
		childLogger.Error().Err(err).Msg("ParseRsaPublicKeyFromPemStr")
		return false, err
	}

	hashed_verify := sha256.Sum256(fileBytesToVerify) 

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed_verify[:], fileBytesSignature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false, err
	}
 
	return true, nil
}

// Encryption Symetric
func (w WorkerService) EncryptDataWithAESKey(aesIdKey string, fileBytesToEncrypt []byte) (*core.FileData, error){
	childLogger.Debug().Msg("EncryptDataWithAESKey")

	//Must have 32 bytes long
	key := []byte(aesIdKey)

	aesBlock, err := aes.NewCipher(key)
    if err != nil {
		childLogger.Error().Err(err).Msg("GetRSAKey")
        return nil, err
    }

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		childLogger.Error().Err(err).Msg("NewGCM")
		return nil, err
	}

	nonce := make([]byte, gcmInstance.NonceSize())
    _, err = rand.Read(nonce)
    if err != nil {
		childLogger.Error().Err(err).Msg("GetRSAKey")
		return nil, err
    }

	cipherText := gcmInstance.Seal(nonce, nonce, fileBytesToEncrypt, nil)

	result := core.FileData{
		FileBytes: cipherText,
		FileBytesB64: base64.StdEncoding.EncodeToString(cipherText),
	}

	return &result, nil
}

// Decrypt Symetric
func (w WorkerService) DecryptDataWithAESKey(aesIdKey string, fileBytesToDecrypt []byte) (*core.FileData, error){
	childLogger.Debug().Msg("DecryptDataWithAESKey")

	//Must have 32 bytes long
	key := []byte(aesIdKey)

	aesBlock, err := aes.NewCipher(key)
    if err != nil {
		childLogger.Error().Err(err).Msg("GetRSAKey")
        return nil, err
    }

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		childLogger.Error().Err(err).Msg("NewGCM")
		return nil, err
	}

	nonceSize := gcmInstance.NonceSize()
	if len(fileBytesToDecrypt) < nonceSize {
		childLogger.Error().Err(err).Msg("file to short")
		return nil, err
    }

	nonce, ciphertext := fileBytesToDecrypt[:nonceSize], fileBytesToDecrypt[nonceSize:]
	res, err := gcmInstance.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		childLogger.Error().Err(err).Msg("NewGCM")
		return nil, err
	}

	result := core.FileData{
		MsgOriginal: string(res),
	}

	return &result, nil
}

// Envelop Encryption
func (w WorkerService) EncryptAESKeyWithRSA(aesIdKey string, rsaIdPublicKey string, fileBytesToEncrypt []byte) (*core.EncryptEnvelopData, error){

	// Encrypt File with AES Key
	cipherFile, err := w.EncryptDataWithAESKey(aesIdKey, fileBytesToEncrypt)
    if err != nil {
		childLogger.Error().Err(err).Msg("EncryptDataWithAESKey")
		return nil, err
    }

	cipherAESKey, err := w.EncryptDataWithRSAKey(rsaIdPublicKey, []byte(aesIdKey) )
    if err != nil {
		childLogger.Error().Err(err).Msg("EncryptDataWithAESKey")
		return nil, err
    }

	result := core.EncryptEnvelopData{
		AESKeyEncrypt: string(cipherAESKey.FileBytesB64),
		FileEncrytpBytesB64: string(cipherFile.FileBytesB64),
	}

	return &result, nil
}

// Envelop Decryption
func (w WorkerService) DecryptAESKeyWithRSA(rsaIdPrivateKey string, fileBytesAESDecrypt []byte, fileBytesToDecrypt []byte) (*core.FileData, error){

	// decrypt AES Key
	decryptAESKey, err := w.DecryptDataWithRSAKey(rsaIdPrivateKey, fileBytesAESDecrypt)
    if err != nil {
		childLogger.Error().Err(err).Msg("DecryptDataWithRSAKey")
		return nil, err
    }

	decryptData, err := w.DecryptDataWithAESKey( decryptAESKey.MsgOriginal , fileBytesToDecrypt)
    if err != nil {
		childLogger.Error().Err(err).Msg("EncryptDataWithAESKey")
		return nil, err
    }

	result := core.FileData{
		MsgOriginal: string(decryptData.MsgOriginal),
	}

	return &result, nil
}
