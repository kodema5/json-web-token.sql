create extension if not exists "uuid-ossp" schema public;
create extension if not exists pgcrypto;

------------------------------------------------------------------------------
-- ddl
\if :local
    drop schema if exists jwt_ cascade;
\endif
create schema if not exists jwt_;
\ir src/jwt_/index.sql


------------------------------------------------------------------------------
-- api
drop schema if exists jwt cascade;
create schema jwt;
\ir src/jwt/index.sql
