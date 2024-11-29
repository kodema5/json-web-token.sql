create schema if not exists jwt_;
set search_path=jwt_,public;

create table if not exists jwt_key (
    -- keys stored in jwt tag
    public_key text
        not null
        primary key,

    -- actual key
    private_key text
        not null,

    -- reserved
    source text,

    -- expiration key
    expired_tz timestamp with time zone
        default (now() + '1 day'::interval)
);

drop schema if exists jwt cascade;
create schema if not exists jwt;
set search_path=jwt,jwt_,public;

\ir base64.js
\ir utf8.sql
\ir jwt_encode.sql
\ir jwt_decode.sql
\ir jwt_recode.sql
\ir gen_keys.sql
\ir prune_keys.sql