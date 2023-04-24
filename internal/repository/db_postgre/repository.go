package db_postgre

import (
	"context"
	"time"

	_ "github.com/lib/pq"
//	"github.com/rs/zerolog/log"

	"github.com/go-card-crypto/internal/core"
	"github.com/go-card-crypto/internal/erro"

)

type WorkerRepository struct {
	databaseHelper DatabaseHelper
}

func NewWorkerRepository(databaseHelper DatabaseHelper) WorkerRepository {
	childLogger.Debug().Msg("NewWorkerRepository")
	return WorkerRepository{
		databaseHelper: databaseHelper,
	}
}

//---------------------------

func (w WorkerRepository) Ping() (bool, error) {
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")
	childLogger.Debug().Msg("Ping")
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")

	ctx, cancel := context.WithTimeout(context.Background(), 1000)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)
	err := client.Ping()
	if err != nil {
		return false, erro.ErrConnectionDatabase
	}

	return true, nil
}

func (w WorkerRepository) AddTenantPublicKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("AddTenantPublicKey")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)

	stmt, err := client.Prepare(`INSERT INTO rsa_key ( 	tenant_id, 
														file_name,
														rsa_public_key, 
														created_date) 
														VALUES( $1, $2, $3, $4) `)

	if err != nil {
		childLogger.Error().Err(err).Msg("Prepare statement")
		return nil, erro.ErrInsert
	}
	_, err = stmt.Exec(	rsaKey.TenantId, 
						rsaKey.FileName, 
						rsaKey.RSAPublicKey,
						time.Now())
	
	return &rsaKey , nil				
}

/*
func (w WorkerRepository) GetPerson(id string) (core.Person, error){
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")
	childLogger.Debug().Msg("GetPerson")
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")

	ctx, cancel := context.WithTimeout(context.Background(), 1000)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)
	person := core.Person{}

	rows, err := client.Query(`SELECT id, email FROM person WHERE id = $1`, id)
	if err != nil {
		log.Error().Err(err).Msg("erro Query")
		return person, erro.ErrConnectionDatabase
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan( &person.ID, &person.Email )
		if err != nil {
			log.Error().Err(err).Msg("erro Scan")
			return person , erro.ErrNotFound
        }
		return person, nil
	}

	return person , erro.ErrNotFound
}

func (w WorkerRepository) AddWebHook(webhook core.WebHook) (error) {	
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")
	childLogger.Debug().Msg("AddWebHook")
	childLogger.Debug().Msg("++++++++++++++++++++++++++++++++")

	ctx, cancel := context.WithTimeout(context.Background(), 1000)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)

	stmt, err := client.Prepare(`INSERT INTO webhook ( 	id, 
														email, 
														url, 
														date_create_at) 
									VALUES( $1, $2, $3, $4) `)
	if err != nil {
		log.Error().Err(err).Msg("erro Prepare")
		return erro.ErrInsert
	}
	_, err = stmt.Exec(	webhook.ID, 
						webhook.Email,
						webhook.URL,
						time.Now())
	if err != nil {
		log.Error().Err(err).Msg("erro Exec")
		return erro.ErrInsert
	}

	return  nil
}
*/