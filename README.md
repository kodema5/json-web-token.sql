# pgsql-json-web-token

[json web token](https://jwt.io) (jwt) for [postgresql](https://www.postgresql.org/)

## install

requires pgcrypto; if pgtap installed, it unit-tests
```
psql -f index.sql
```

## expression as key

because a static key can be potentially dangerous,
when command_string_t will be executed with payload ($1) for secret-key text

```
to_jwt(payload jsonb, cmd command_string_t)
from_jwt(token_t, cmd command_string_t)
```

example
```
dev=# select to_jwt(
    '{"sub":"1234567890","name":"John Doe","admin":true}',
    'select $1->>''sub'''::jwt.command_string_t);
                                                                              to_jwt

------------------------------------------------------------------------------------------------------------------------------------------------------------------
 eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.Wr2gkxnRx0ujcas6lMwiwbk0a-eVGqD2Pu4Xar2CzQc
(1 row)

dev=# select from_jwt(
    'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.Wr2gkxnRx0ujcas6lMwiwbk0a-eVGqD2Pu4Xar2CzQc',
    'select $1->>''sub'''::jwt.command_string_t);
                         from_jwt
----------------------------------------------------------
 {"sub": "1234567890", "name": "John Doe", "admin": true}
(1 row)
```

## text as key

supposed key is produced by other mean, ex: a constant / variable

```
to_jwt(payload jsonb, key text)
from_jwt(token_t, key text)
```
example
```
dev=# select to_jwt(
    '{"sub":"1234567890","name":"John Doe","admin":true}',
    coalesce(current_setting('jwt.key',true), 'secret'));
                                                                              to_jwt

------------------------------------------------------------------------------------------------------------------------------------------------------------------
 eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.cvIR8w__qQnVs9joUjqFvS4xMtm9SDduo-dytWgZGjE
(1 row)

dev=# select from_jwt(
    'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0.cvIR8w__qQnVs9joUjqFvS4xMtm9SDduo-dytWgZGjE',
    coalesce(current_setting('jwt.key',true), 'secret'));
                         from_jwt
----------------------------------------------------------
 {"sub": "1234567890", "name": "John Doe", "admin": true}
(1 row)

```
