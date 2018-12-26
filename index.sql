\if :pgsql_json_web_token
\else
\set pgsql_json_web_token true


-- https://jwt.io
-- inspired by https://github.com/michelp/pgjwt

create extension if not exists pgcrypto;
drop schema if exists jwt cascade;
create schema jwt;

\i base64.sql
\i utf8.sql
\i hash.sql

-- jwt is a text
create domain jwt.token_t as text;

\i key_text.sql
\i key_cmd.sql

\i test.sql

\endif