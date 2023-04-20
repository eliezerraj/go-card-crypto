package service

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-card-crypto/internal/repository/db_postgre"
	"github.com/go-card-crypto/internal/core"

)

var (
	tableName = "card"
	keyPhrase = "mykey-eliezer-1234567890"
	envDB	core.DatabaseRDS
	dataBaseHelper 	db_postgre.DatabaseHelper
	repoDB	db_postgre.WorkerRepository
	logLevel 	= zerolog.DebugLevel
)

func init(){
	log.Debug().Msg("init")
	envDB.Host = "host.docker.internal"
	envDB.Port = "5432"
	envDB.Schema = "public"
	envDB.DatabaseName = "postgres"
	envDB.User  = "admin"
	envDB.Password  = "admin"
	envDB.Db_timeout = 90
	envDB.Postgres_Driver = "postgres"
}

func TestCreateAESKey(t *testing.T) {
	zerolog.SetGlobalLevel(logLevel)

	t.Logf("Success on TestAddCard!!!")

	count := 1
	var err error
	for {
		dataBaseHelper, err = db_postgre.NewDatabaseHelper(envDB)
		if err != nil {
			if count < 3 {
				log.Error().Err(err).Msg("Erro na abertura do Database")
			} else {
				log.Error().Err(err).Msg("EERRO FATAL na abertura do Database aborting")
				panic(err)	
			}
			time.Sleep(3 * time.Second)
			count = count + 1
			continue
		}
		break
	}
	repoDB = db_postgre.NewWorkerRepository(dataBaseHelper)
	workerService := NewWorkerService(&repoDB)

	cipherText , err := workerService.CreateAESKey(keyPhrase)
	if err != nil {
		t.Errorf("Error -TestGetRSAKey - GetRSAKey %v ", err)
	}

	t.Logf("Success on TestAddCard!!! %v ",cipherText )

}