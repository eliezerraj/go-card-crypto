# go-card-crypto
go-card-crypto

DROP TABLE public."rsa_key";

CREATE TABLE public."rsa_key" (
	id serial4 NOT NULL,
	tenant_id varchar(100) NULL,
	file_name	varchar(100) NULL,
	rsa_public_key varchar(100) null,
	created_date timestamp
);