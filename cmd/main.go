package main

import(
	"os"
	"time"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-card-crypto/internal/repository/db_postgre"
	"github.com/go-card-crypto/internal/core"
	"github.com/go-card-crypto/internal/service"
	"github.com/go-card-crypto/internal/adapter/handler"

)

var(
	logLevel 	= zerolog.DebugLevel
	tableName 	= "tenant_key"
	version 	= "card crypto version 1.0"
	httpAppServer 		core.HttpAppServer
	server				core.Server
	envDB	 			core.DatabaseRDS
	dataBaseHelper 		db_postgre.DatabaseHelper
	repoDB				db_postgre.WorkerRepository
	//workerService		service.WorkerService
)

func init(){
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)

	envDB.Host = "127.0.0.1" //"host.docker.internal"
	envDB.Port = "5432"
	envDB.Schema = "public"
	envDB.DatabaseName = "postgres"
	envDB.User  = "admin"
	envDB.Password  = "admin"
	envDB.Db_timeout = 90
	envDB.Postgres_Driver = "postgres"

	server.Port = 5000
	server.ReadTimeout = 60
	server.WriteTimeout = 60
	server.IdleTimeout = 60
	server.CtxTimeout = 60

	httpAppServer.Server = server

	getEnv()
}

func getEnv() {
	log.Debug().Msg("getEnv")
	if os.Getenv("TABLE_NAME") !=  "" {
		tableName = os.Getenv("TABLE_NAME")
	}
	if os.Getenv("LOG_LEVEL") !=  "" {
		if (os.Getenv("LOG_LEVEL") == "DEBUG"){
			logLevel = zerolog.DebugLevel
		}else if (os.Getenv("LOG_LEVEL") == "INFO"){
			logLevel = zerolog.InfoLevel
		}else if (os.Getenv("LOG_LEVEL") == "ERROR"){
				logLevel = zerolog.ErrorLevel
		}else {
			logLevel = zerolog.InfoLevel
		}
	}
	if os.Getenv("VERSION") !=  "" {
		version = os.Getenv("VERSION")
	}
	if os.Getenv("PORT") !=  "" {
		intVar, _ := strconv.Atoi(os.Getenv("PORT"))
		httpAppServer.Server.Port = intVar
	}

	if os.Getenv("DB_HOST") !=  "" {
		envDB.Host = os.Getenv("DB_HOST")
	}
	if os.Getenv("DB_PORT") !=  "" {
		envDB.Port = os.Getenv("DB_PORT")
	}
	if os.Getenv("DB_USER") !=  "" {
		envDB.User = os.Getenv("DB_USER")
	}
	if os.Getenv("DB_PASSWORD") !=  "" {	
		envDB.Password = os.Getenv("DB_PASSWORD")
	}
	if os.Getenv("DB_NAME") !=  "" {	
		envDB.DatabaseName = os.Getenv("DB_NAME")
	}
	if os.Getenv("DB_SCHEMA") !=  "" {	
		envDB.Schema = os.Getenv("DB_SCHEMA")
	}

}

func main() {
	log.Debug().Msg("*** go card crypto")
	log.Debug().Msg("-------------------")
	log.Debug().Str("version", version).
				Str("tableName", tableName).
				Msg("Enviroment Variables")
	log.Debug().Msg("--------------------")

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

	workerService := service.NewWorkerService(&repoDB)

	httpWorkerAdapter := handler.NewHttpWorkerAdapter(workerService)
	httpServer := handler.NewHttpAppServer(httpAppServer)

	httpServer.StartHttpAppServer(httpWorkerAdapter)
}