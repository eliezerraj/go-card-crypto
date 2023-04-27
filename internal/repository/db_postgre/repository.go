package db_postgre

import (
	"context"
	"time"

	_ "github.com/lib/pq"

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

func (w WorkerRepository) AddRSAKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("AddRSAKey")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)

	stmt, err := client.Prepare(`INSERT INTO rsa_key ( 	tenant_id, 
														host_id,
														file_name,
														type_key,
														rsa_public_key, 
														status,
														created_date) 
														VALUES( $1, $2, $3, $4, $5, $6, $7) `)

	if err != nil {
		childLogger.Error().Err(err).Msg("Prepare statement")
		return nil, erro.ErrInsert
	}
	_, err = stmt.Exec(	rsaKey.TenantId, 
						rsaKey.HostId, 
						rsaKey.FileName, 
						rsaKey.TypeKey,
						rsaKey.RSAPublicKey,
						rsaKey.Status,
						time.Now())
	
	return &rsaKey , nil				
}

func (w WorkerRepository) GetRSAKey(rsaKey core.RSA_Key) (*core.RSA_Key, error){
	childLogger.Debug().Msg("GetRSAKey")
	childLogger.Debug().Interface("",rsaKey).Msg("GetRSAKey")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := w.databaseHelper.GetConnection(ctx)
	result_rsaKey := core.RSA_Key{}

	rows, err := client.Query(`SELECT rsa_public_key, host_id, tenant_id 
								FROM rsa_key 
								WHERE status = $1 
								and tenant_id =$2
								and host_id =$3`, rsaKey.Status, rsaKey.TenantId, rsaKey.HostId)
	if err != nil {
		childLogger.Error().Err(err).Msg("Query statement")
		return nil, erro.ErrConnectionDatabase
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan( &result_rsaKey.RSAPublicKey, &result_rsaKey.HostId, &result_rsaKey.TenantId )
		if err != nil {
			childLogger.Error().Err(err).Msg("Scan statement")
			return nil, erro.ErrNotFound
        }
		return &result_rsaKey, nil
	}

	return nil, erro.ErrNotFound
}
