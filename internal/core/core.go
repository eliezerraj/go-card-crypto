package core

import (
	"time"

)

type DatabaseRDS struct {
    Host 				string `json:"host"`
    Port  				string `json:"port"`
	Schema				string `json:"schema"`
	DatabaseName		string `json:"databaseName"`
	User				string `json:"user"`
	Password			string `json:"password"`
	Db_timeout			int	`json:"db_timeout"`
	Postgres_Driver		string `json:"postgres_driver"`
}

type HttpAppServer struct {
	AppInfo 	*AppInfo 		`json:"app_info"`
	Server     	Server     		`json:"server"`
}

type AppInfo struct {
	Name 				string `json:"name"`
	Description 		string `json:"description"`
	Version 			string `json:"version"`
	OSPID				string `json:"os_pid"`
	IpAdress			string `json:"ip_adress"`
}

type Server struct {
	Port 			int `json:"port"`
	ReadTimeout		int `json:"readTimeout"`
	WriteTimeout	int `json:"writeTimeout"`
	IdleTimeout		int `json:"idleTimeout"`
	CtxTimeout		int `json:"ctxTimeout"`
}
//

type FileEncrypted struct{
	FileData		string 		`json:"file_data"`
	RSAHosttKeyName	string 		`json:"rsa_host_key_name"`
}

//-------------
type RSA_Key struct{
	HostId	 		string 		`json:"host_id"`
	TenantId 		string 		`json:"tenant_id"`
	FileName		string 		`json:"file_name"`
	TypeKey			string 		`json:"type_key"`
	RSAPublicKey	string 		`json:"rsa_public_key"`
	RSAPublicKeyByte []byte 	`json:"rsa_public_key_byte"`
	Status			string 		`json:"status"`
	CreatedDate  	time.Time 	`json:"created_date,omitempty"`
}

func NewRSAKey(options ...func(*RSA_Key)) *RSA_Key {
	x := &RSA_Key{}
	for _, o := range options {
	  o(x)
	}
	return x
}

func WithFileName(filename string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.FileName = filename
	}
}
func WithHostId(hostId string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.HostId = hostId
	}
}
func WithTenantId(tenantId string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.TenantId = tenantId
	}
}
func WithRSAPublicKey(rsaPublicKey string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.RSAPublicKey = rsaPublicKey
	}
}
func WithStatus(status string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.Status = status
	}
}
func WithRSAPublicKeyBytes(rsaPublicKeyByte []byte) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.RSAPublicKeyByte = rsaPublicKeyByte
	}
}
func WithTypeKey(typeKey string) func(*RSA_Key) {
	return func(s *RSA_Key) {
	  s.TypeKey = typeKey
	}
}
//-------------