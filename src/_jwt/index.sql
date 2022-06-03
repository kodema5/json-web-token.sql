\if :local
    drop schema if exists _jwt cascade;
\endif
create schema if not exists _jwt;

-- contains shared private keys
-- ex: mi-jwt-key.v1
--
create table if not exists _jwt.key (
    id text
        not null
        primary key,

    value text
        not null,

    until_tz timestamp with time zone
        default (now() + '1 day'::interval)

);

