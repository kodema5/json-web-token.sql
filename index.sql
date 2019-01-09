\if :pgsql_json_web_token
\else
\set pgsql_json_web_token true


-- https://jwt.io
-- inspired by https://github.com/michelp/pgjwt

create extension if not exists pgcrypto;
drop schema if exists jwt cascade;
create schema jwt;

\ir base64.sql
\ir utf8.sql
\ir hash.sql

-- jwt is a text
create domain jwt.token_t as text;

\ir jwt_w_text_key.sql
\ir jwt_w_cmd_key.sql

\ir tests/index.sql

\endif