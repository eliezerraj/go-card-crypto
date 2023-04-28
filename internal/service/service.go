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
	b64 "encoding/base64"
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
func (w WorkerService) DecryptDataWithRSAKey(rsaIdPrivateKey string, fileBytesToDecrypt []byte) (string, error){
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
		return "", err
	}
	privPem, err := base64.StdEncoding.DecodeString(resp.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return "", err
	}
	// to validate the RDA priv Key
	privateKey, err :=ParseRsaPrivateKeyFromPemStr(privPem)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := privateKey.Decrypt(	nil, 
												fileBytesToDecrypt,
												&rsa.OAEPOptions{Hash: crypto.SHA256})

	return string(decryptedBytes), nil
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












// Check signature
func (w WorkerService) CheckSignatureRSA(rsaIdVerifyKey string, fileBytesEncrypt []byte, fileBytesSignature []byte) (bool, error){
	childLogger.Debug().Msg("CheckSignatureRSA")

	status := "ACTIVE" 
	typeKey := "rsa_public" 

	// Retrieve RDS pub-key
	rsa_key := core.NewRSAKey(
		core.WithTenantId(rsaIdVerifyKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdVerifyKey),
		core.WithStatus(status),
	)

	res, err := w.workerRepository.GetRSAKey(*rsa_key)
	if err != nil {
		return false, err
	}

	pubPem, err := base64.StdEncoding.DecodeString(res.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return false, err
	}
	// to validate the RDA pub Key
	publicKey, err :=ParseRsaPublicKeyFromPemStr(pubPem)
	if err != nil {
		return false, err
	}

    //
	typeKey = "rsa_private" 
	rsa_key_p := core.NewRSAKey(
		core.WithTenantId(rsaIdVerifyKey),
		core.WithTypeKey(typeKey),
		core.WithHostId(rsaIdVerifyKey),
		core.WithStatus(status),
	)
	resp, err := w.workerRepository.GetRSAKey(*rsa_key_p)
	if err != nil {
		return false, err
	}
	privPem, err := base64.StdEncoding.DecodeString(resp.RSAPublicKey)
	if err != nil {
		childLogger.Error().Err(err).Msg("DecodeString")
		return false, err
	}
	// to validate the RDA priv Key
	privateKey, err :=ParseRsaPrivateKeyFromPemStr(privPem)
	if err != nil {
		return false, err
	}

	msg := []byte("verifiable message")

	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false, err
	}

	fmt.Println("signature verified")

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